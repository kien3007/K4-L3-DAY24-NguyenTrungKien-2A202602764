"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu một dòng còn trong file bị sửa mà không tính lại
        hash, nếu xoá/chèn giữa file làm đứt liên kết, hoặc thiếu reason.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(data: dict) -> str:
    """Tính SHA256 cho bản ghi ledger (không bao gồm chính field 'hash')."""
    payload = {k: v for k, v in data.items() if k != "hash"}
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Thêm một bản ghi vào audit ledger với hash chain."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists() and path.stat().st_size > 0:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            try:
                last_record = json.loads(lines[-1])
                prev_hash = last_record.get("hash", "0" * 64)
            except Exception:
                pass

    record = dict(entry)
    record["prev_hash"] = prev_hash
    record["hash"] = _compute_hash(record)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    """Kiểm tra tính toàn vẹn của audit ledger."""
    path = Path(path)
    if not path.exists():
        return True

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev = "0" * 64
    for line in lines:
        try:
            record = json.loads(line)
        except Exception:
            return False

        # Mọi dòng phải có reason non-empty
        if not record.get("reason"):
            return False

        # Kiểm tra chuỗi liên kết prev_hash
        if record.get("prev_hash") != expected_prev:
            return False

        # Tính lại hash kiểm tra tính toàn vẹn nội dung
        current_hash = record.get("hash")
        computed_hash = _compute_hash(record)
        if current_hash != computed_hash:
            return False

        expected_prev = current_hash

    return True
