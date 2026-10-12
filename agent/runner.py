"""BƯỚC 3c & 3d — Trifecta split + OBO + Egress containment.

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt:
- Run A: gọi search_docs (untrusted content). KHÔNG gọi read_customer / http_post.
- Run B: gọi read_customer (private data) theo ticket_id từ tên file -> related_tickets.
  Kiểm tra quyền OBO và policy trước khi gọi tool.
- Egress: http_post đi kèm restricted data phải bị policy chặn (restricted + egress -> deny).
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _get_ticket_id_from_filename(filename: str) -> int | None:
    match = re.search(r"ticket-(\d+)", filename)
    if match:
        return int(match.group(1))
    return None


def _load_customers() -> list[dict]:
    if CUSTOMERS_FILE.exists():
        try:
            return json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Xử lý yêu cầu người dùng qua Trifecta Split và kiểm soát quyền OBO."""
    log_dir = Path(log_dir) if log_dir else REPORTS_DIR
    ledger_path = log_dir / "ledger.jsonl"

    session_id = uuid.uuid4().hex[:8]
    agent_id = "lab24-agent"
    run_id_a = f"run-a-{session_id}"
    run_id_b = f"run-b-{session_id}"

    now_dt = datetime.now(timezone.utc)
    expires_at = (now_dt + timedelta(hours=1)).isoformat()

    # =========================================================================
    # RUN A: Đọc untrusted content (corpus/), sanitize PII
    # KHÔNG gọi read_customer, KHÔNG gọi http_post
    # =========================================================================
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{agent_id}/{run_id_a}",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs", "read_customer"),
        parent_scopes=(),
        expires_at=expires_at,
    )
    allowed_search, reason_search = policy.check(ctx_search)
    args_search_hash = hashlib.sha256(
        json.dumps({"query": message}, sort_keys=True).encode("utf-8")
    ).hexdigest()

    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id_a,
            "tool": "search_docs",
            "args_hash": args_search_hash,
            "classification": "internal",
            "decision": "allow" if allowed_search else "deny",
            "reason": reason_search,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        },
        ledger_path,
    )

    if not allowed_search:
        return "Yêu cầu bị từ chối bởi chính sách bảo mật."

    raw_docs = tools.search_docs(message)

    # Sanitize PII trước khi truyền dữ liệu qua boundary
    sanitized_docs = [
        {"id": d["id"], "text": pii.redact(d["text"])} for d in raw_docs
    ]

    # Quét injection để phát hiện chỉ thị của attacker
    combined_raw_text = "\n\n".join(d["text"] for d in raw_docs)
    injected = llm.find_injection(combined_raw_text)

    # Trích xuất ticket_id có kiểu int từ TÊN FILE
    matched_ticket_ids: set[int] = set()
    for d in raw_docs:
        tid = _get_ticket_id_from_filename(d["id"])
        if tid is not None:
            matched_ticket_ids.add(tid)

    # =========================================================================
    # RUN B: Truy xuất private data (customers.json)
    # KHÔNG nhận free text từ attacker; suy customer_id từ related_tickets
    # =========================================================================
    customers = _load_customers()
    target_customer_ids: list[str] = []
    for c in customers:
        c_tickets = set(c.get("related_tickets", []))
        if matched_ticket_ids & c_tickets:
            target_customer_ids.append(c["customer_id"])

    collected_records = []
    for cid in target_customer_ids:
        # Kiểm tra policy OBO TRƯỚC KHI gọi read_customer
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/{run_id_b}",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=(),
            expires_at=expires_at,
        )
        allowed_read, reason_read = policy.check(ctx_read)
        args_read_hash = hashlib.sha256(
            json.dumps({"customer_id": cid}, sort_keys=True).encode("utf-8")
        ).hexdigest()

        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "run_id": run_id_b,
                "tool": "read_customer",
                "args_hash": args_read_hash,
                "classification": "restricted",
                "decision": "allow" if allowed_read else "deny",
                "reason": reason_read,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if allowed_read:
            try:
                rec = tools.read_customer(cid)
                collected_records.append(rec)
            except tools.ToolError:
                pass

    # Xử lý egress an toàn nếu có chỉ thị injection
    if injected is not None:
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/{run_id_b}",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=(),
            expires_at=expires_at,
        )
        allowed_post, reason_post = policy.check(ctx_post)
        args_post_hash = hashlib.sha256(
            json.dumps({"target_url": injected.target_url}, sort_keys=True).encode("utf-8")
        ).hexdigest()

        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "run_id": run_id_b,
                "tool": "http_post",
                "args_hash": args_post_hash,
                "classification": "restricted",
                "decision": "allow" if allowed_post else "deny",
                "reason": reason_post,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if allowed_post:
            tools.http_post(injected.target_url, {"records": collected_records})

    return llm.summarize(sanitized_docs)
