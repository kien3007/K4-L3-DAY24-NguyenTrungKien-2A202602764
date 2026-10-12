# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
- **Dữ liệu nhạy cảm / PII (`restricted`)**: Bao gồm mã khách hàng (`customer_id`), họ tên, số Căn cước công dân (12 chữ số), số điện thoại di động (10 chữ số), số tài khoản ngân hàng (STK 10–16 chữ số) và địa chỉ email cá nhân được lưu trữ trong `data/customers.json`.
- **Dữ liệu nội bộ (`internal`)**: Toàn bộ nội dung các ticket hỗ trợ khách hàng, ghi chú kỹ thuật và thông tin trao đổi nội bộ trong thư mục `corpus/ticket-*.md`.
- **Dữ liệu công khai (`public`)**: Các câu hỏi chung của người dùng, tài liệu hướng dẫn và thông tin chương trình khuyến mãi không gắn với cá nhân cụ thể.

2. Mục đích xử lý và principal:
- **Mục đích xử lý (`request_purpose`)**:
  - `summarize-tickets`: Tổng hợp danh sách và tình trạng xử lý các yêu cầu hỗ trợ khách hàng trong tuần.
  - `support-reply`: Tra cứu hồ sơ khách hàng để phản hồi và giải quyết khiếu nại đối soát tài chính theo ticket hợp lệ.
  - `privacy-audit`: Kiểm tra việc tuân thủ bảo vệ dữ liệu cá nhân theo quy định.
- **Chủ thể ủy quyền (`principal`)**:
  - `support_l1`: Nhân viên trực hỗ trợ L1, chỉ được thực hiện tìm kiếm ticket (`search_docs`) với mục đích `summarize-tickets`, bị nghiêm cấm truy cập hồ sơ khách hàng (`read_customer`) chứa CCCD/STK.
  - `dpo`: Cán bộ bảo vệ dữ liệu, được phép đọc hồ sơ khách hàng (`read_customer`) cho mục đích `support-reply` / `privacy-audit` để phục vụ đối soát hợp lệ.
  - `billing`: Bộ phận kế toán thanh toán, được phép đọc thông tin tài khoản cho mục đích đối soát hóa đơn (`billing-reconciliation`).

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- **Run A (Xử lý tài liệu & khử định danh)**: Nhận truy vấn từ người dùng, gọi `tools.search_docs()` để đọc toàn văn các ticket từ `corpus/`. Dữ liệu văn bản được lọc và che giấu qua `agent.pii.redact()`. Ranh giới giữa hai run chỉ cho phép truyền mảng số nguyên `ticket_id` (trích xuất từ tên file) sang Run B. Toàn bộ free text của người dùng/kẻ tấn công bị chặn lại tại Run A. Run A không có quyền gọi `read_customer` hay `http_post`.
- **Run B (Truy xuất dữ liệu riêng tư)**: Nhận `ticket_id` từ Run A, suy ra `customer_id` thông qua trường tin cậy `related_tickets` trong `data/customers.json`. Sau khi được PEP phê duyệt, Run B gọi `tools.read_customer()` để đọc thông tin khách hàng hợp lệ.
- **Endpoint mạng (Egress)**: Kẻ tấn công cố tình điều hướng gửi dữ liệu về sink tại `http://127.0.0.1:10024/reconcile`. Tuy nhiên, cổng PEP chặn đứng lệnh gọi `tools.http_post` do vi phạm quy tắc tối thiểu (`restricted` + `egress` -> deny). Không có bất kỳ byte dữ liệu nào bị gửi ra endpoint mạng.

4. Bằng chứng deny/allow và giới hạn của mock:
- **Bằng chứng thực nghiệm**:
  - Quyết định `allow`: Khi chạy dưới quyền `dpo`, `reports/ledger.jsonl` ghi nhận các lượt gọi `read_customer` hợp lệ cho khách hàng gắn với ticket; agent hoàn thành nhiệm vụ tổng hợp thông tin cho người dùng.
  - Quyết định `deny`: Dưới quyền `support_l1`, mọi nỗ lực gọi `read_customer` đều bị từ chối (`decision="deny"`). Dưới quyền `dpo`, nỗ lực gửi PII ra mạng của attacker bị từ chối (`tool="http_post", decision="deny"`).
  - Bằng chứng exfiltration: File `reports/attack-after.log` hoàn toàn rỗng (0 bytes), chứng minh cuộc tấn công đánh cắp dữ liệu thất bại hoàn toàn.
- **Giới hạn của môi trường Mock**:
  - Mô hình MockLLM trong lab là mô hình tất định dựa trên so khớp từ khóa/marker, chưa phản ánh đầy đủ tính phi tất định (non-deterministic) và các kỹ thuật bẻ khóa prompt (jailbreak/obfuscation) phức tạp của các LLM thực tế ngoài đời.
  - Cơ chế danh tính `--as` qua `data/principals.json` chỉ mô phỏng tầng kiểm soát phân quyền (ABAC/RBAC), chưa tích hợp hệ thống xác thực danh tính thực tế (như mTLS, OIDC/OAuth2 tokens, PKI).
  - Sink exfiltration chỉ thử nghiệm trên localhost (`127.0.0.1:10024`), chưa bao quát các kênh exfiltration gián tiếp khác như DNS tunneling, SSRF ngầm hay kênh phụ (timing side-channels).

