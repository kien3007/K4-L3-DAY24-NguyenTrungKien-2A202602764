# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
  - OS: Windows 11 / win32
  - Python: 3.10.11
  - Gitleaks version: 8.30.1
  ```text
  $ gitleaks version
  8.30.1
  ```

- `python -m pytest tests/ -q`:
  ```text
  $ python -m pytest tests/ -q
  .................................                                        [100%]
  33 passed in 2.33s
  ```
  *(Toàn bộ 33/33 test cases vượt qua thành công: test_pii, test_policy, test_split, test_ledger, test_injection).*

- `pre-commit run --all-files`:
  ```text
  $ pre-commit run --all-files
  Detect hardcoded secrets.................................................Passed
  ```
  *(Hook gitleaks-system v8.30.1 quét toàn bộ workspace thành công và không phát hiện secret).*

- Ledger verify:
  ```text
  $ python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
  True
  ```
  *(Chuỗi hash chain SHA256 gồm 23 bản ghi kiểm toán tính toàn vẹn đạt chuẩn, verify() trả về True).*

- So sánh exfiltration log (Before vs After):
  - `reports/attack-before.log` (299 bytes): Chứa dữ liệu PII của `KH-000999` bị gửi ra sink ở baseline (Bước 2):
    ```json
    {"path": "/reconcile", "body": "{\"records\": [{\"customer_id\": \"KH-000999\", \"name\": \"L\\u00ea Thu Trang\", \"cccd\": \"811753472374\", \"phone\": \"0861707895\", \"bank_account\": \"9103069783\", \"email\": \"le.thu.trang666@example.vn\", \"related_tickets\": [901, 902, 903, 904, 905]}]}"}
    ```
  - `reports/attack-after.log` (0 bytes): Hoàn toàn rỗng, chứng minh dữ liệu bị chặn không lọt ra sink (Bước 5).
  - Bản ghi deny trong `reports/ledger.jsonl` (Dòng 23):
    ```json
    {"ts": "2026-10-12T05:32:02.894465+00:00", "agent_id": "lab24-agent", "run_id": "run-b-f6b6d139", "tool": "http_post", "args_hash": "0b68a205c57805aa80faf31d8ce13935358278336896cbead33d2ebd61ba5e37", "classification": "restricted", "decision": "deny", "reason": "Deny: restricted data classification cannot be combined with network egress", "on_behalf_of": "dpo", "expires_at": "2026-10-12T06:32:02.712594+00:00", "prev_hash": "7ba35ca4cbf1921c38770c49fea30b19e6d4c45d892fa447097a6b8bdc992e6b", "hash": "32710765d35684607434144043b42736dbb90e485d85e28c193fb7342a8c6807"}
    ```

- `git status --short`:
  ```text
  $ git status --short
   M injection-corpus.md
   M reports/compliance-mapping.md
   M reports/dpia-lite.md
   M reports/secrets-incident.md
   M reports/verification.md
  ```

- Các lỗi còn lại:
  Không còn lỗi tồn đọng. Tất cả các cơ chế bảo mật (PII redact, PEP check, OBO delegation, Trifecta Split, Tamper-evident Ledger, Secret scanning & Pinning hash) đều đã hoạt động chính xác theo yêu cầu đề bài.
