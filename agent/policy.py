"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PRINCIPALS_FILE = BASE_DIR / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    if PRINCIPALS_FILE.exists():
        try:
            return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách trước khi thực thi tool.

    Trả về (allow, reason). Mọi quyết định (cả allow lẫn deny) đều có lý do rõ ràng.
    """
    # 1. Rule tối thiểu: Dữ liệu restricted đi kèm network egress phải bị chặn tuyệt đối
    if context.data_classification == "restricted" and context.egress_enabled:
        return (
            False,
            "Deny: restricted data classification cannot be combined with network egress",
        )

    # 2. Kiểm tra hạn sử dụng của phiên làm việc (expires_at)
    if context.expires_at:
        try:
            expires_dt = datetime.fromisoformat(context.expires_at)
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=timezone.utc)
            if expires_dt <= datetime.now(timezone.utc):
                return (False, f"Deny: execution context expired at {context.expires_at}")
        except Exception:
            return (False, f"Deny: invalid expires_at timestamp format '{context.expires_at}'")

    # 3. Kiểm tra danh tính ủy quyền và quyền hạn của principal (OBO)
    if context.principal_id:
        principals = _load_principals()
        if context.principal_id not in principals:
            return (False, f"Deny: unknown principal_id '{context.principal_id}'")

        principal_info = principals[context.principal_id]
        allowed_tools = set(principal_info.get("allowed_tools", []))
        allowed_purposes = set(principal_info.get("purposes", []))

        # Kiểm tra mục đích gọi tool
        if context.request_purpose and allowed_purposes and context.request_purpose not in allowed_purposes:
            return (
                False,
                f"Deny: purpose '{context.request_purpose}' is not permitted for principal '{context.principal_id}'",
            )

        # Kiểm tra tool được yêu cầu
        if context.requested_tool:
            if context.requested_tool not in allowed_tools:
                return (
                    False,
                    f"Deny: tool '{context.requested_tool}' is not permitted for principal '{context.principal_id}'",
                )

            # Phải nằm trong phạm vi quyền của agent
            if context.agent_scopes and context.requested_tool not in context.agent_scopes:
                return (
                    False,
                    f"Deny: tool '{context.requested_tool}' exceeds agent_scopes",
                )

            # Nếu có ủy quyền trung gian (delegation_depth > 0), không được vượt quyền agent cha
            if context.delegation_depth > 0:
                if not context.parent_scopes or context.requested_tool not in context.parent_scopes:
                    return (
                        False,
                        f"Deny: delegation depth {context.delegation_depth} cannot expand parent_scopes for tool '{context.requested_tool}'",
                    )

    tool_desc = context.requested_tool or "requested operation"
    principal_desc = context.principal_id or "anonymous"
    return (
        True,
        f"Allow: policy check passed for {tool_desc} under principal '{principal_desc}' (classification={context.data_classification})",
    )
