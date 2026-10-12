"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Nhận diện và che giấu (redact) 4 loại thông tin định danh cá nhân (PII):
- VN_CCCD: 12 chữ số liên tiếp
- VN_PHONE: 10 chữ số bắt đầu bằng 0 (có thể có dấu cách / gạch ngang)
- VN_BANK_ACCOUNT: 8-19 chữ số liên tiếp đi kèm tiền tố STK/số tài khoản
- EMAIL: định dạng chuẩn email

Đo bằng: pytest tests/test_pii.py -v -s
"""
from __future__ import annotations

import re

# Regex patterns cho 4 loại PII
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# STK thường đi kèm tiền tố như STK, số tài khoản,... độ dài từ 8 đến 19 chữ số
_BANK_ACCOUNT_RE = re.compile(
    r"(?i)(?:STK|số tài khoản|so tai khoan|tài khoản|tai khoan)\s*:?\s*(\d{8,19})\b"
)

# CCCD: 12 chữ số liên tiếp
_CCCD_RE = re.compile(r"\b\d{12}\b")

# SĐT Việt Nam: bắt đầu bằng 0, tổng 10 chữ số (hoặc có dấu cách / gạch ngang)
_PHONE_RE = re.compile(r"\b0(?:\d{9}|\d{2,3}[-.\s]\d{3}[-.\s]\d{3,4})\b")


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL.

    Trả về danh sách dict: [{"type": str, "start": int, "end": int}] sắp xếp theo start offset.
    """
    if not text:
        return []

    entities: list[dict] = []
    occupied: set[int] = set()

    # 1. EMAIL (bắt trước vì có thể chứa số)
    for m in _EMAIL_RE.finditer(text):
        start, end = m.start(), m.end()
        entities.append({"type": "EMAIL", "start": start, "end": end})
        occupied.update(range(start, end))

    # 2. VN_BANK_ACCOUNT (bắt trước CCCD/PHONE để tránh nhầm số tài khoản 10 hay 12 chữ số)
    for m in _BANK_ACCOUNT_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        if not any(i in occupied for i in range(start, end)):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})
            occupied.update(range(start, end))

    # 3. VN_CCCD (12 chữ số)
    for m in _CCCD_RE.finditer(text):
        start, end = m.start(), m.end()
        if not any(i in occupied for i in range(start, end)):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})
            occupied.update(range(start, end))

    # 4. VN_PHONE (10 chữ số bắt đầu bằng 0)
    for m in _PHONE_RE.finditer(text):
        start, end = m.start(), m.end()
        if not any(i in occupied for i in range(start, end)):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})
            occupied.update(range(start, end))

    entities.sort(key=lambda e: e["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế các entity PII phát hiện được bằng [REDACTED_<TYPE>].

    Thay thế từ cuối văn bản lên đầu để không làm lệch offset ký tự.
    """
    if not text:
        return text

    entities = detect(text)
    # Sắp xếp giảm dần theo vị trí start để thay thế an toàn
    for e in sorted(entities, key=lambda x: x["start"], reverse=True):
        entity_type = e["type"]
        text = text[: e["start"]] + f"[REDACTED_{entity_type}]" + text[e["end"] :]
    return text
