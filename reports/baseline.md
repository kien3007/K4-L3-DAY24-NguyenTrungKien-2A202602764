# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa có. Khi kiểm tra hàm `_naive_loop()` trong file `agent/loop.py` (dòng 27–55), hàm chỉ nhận vào hai tham số là `message` và `llm`. Ở đây hoàn toàn không tạo hay quản lý bất kỳ định danh nào như `run_id`, `agent_id` hay `principal_id`. Mỗi lượt chạy đều diễn ra ẩn danh, không có context phiên làm việc riêng.

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có ai hay cơ chế phân quyền (PEP) nào cho phép cả. Agent đơn thuần làm theo chỉ thị bị tiêm (prompt injection) từ dữ liệu untrusted trong corpus:
- Trong `agent/loop.py` tại hàm `_naive_loop()` (dòng 43–44): khi `llm.find_injection()` phát hiện chỉ thị độc hại, code sẽ tự động lấy danh sách khách hàng rồi gọi thẳng `tools.http_post(injected.target_url, {"records": collected})` mà không qua bất kỳ bước kiểm tra quyền (policy check) nào.
- Trong `agent/tools.py` tại hàm `http_post()` (dòng 68–85): chỉ có một allowlist cứng ở mức mạng để ép request trỏ về `127.0.0.1:10024` nhằm tránh bắn ra ngoài Internet thật, chứ đây không phải là một tầng kiểm soát quyền (authorization/PEP).

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Bằng chứng nằm ở file log của sink tại `reports/sink.log` (được copy thành `reports/attack-before.log` khi red team). Vì bản thân agent chưa có audit ledger nội bộ nên không lưu lại dấu vết gì, chỉ có phía sink lưu lại request nhận được:
- Trong `sink/sink.py`, hàm `make_handler()` tại phương thức `Handler.do_POST()` (dòng 42–50): mỗi khi nhận request POST, sink sẽ decode toàn bộ body rồi ghi thẳng một dòng JSON vào `reports/sink.log`. Trong file log này sẽ thấy rõ danh sách PII của khách hàng (ví dụ record của `KH-000999`) bị gửi ra ngoài.
- Dữ liệu này được đẩy đi từ lệnh gọi `tools.http_post` ở dòng 44 trong hàm `_naive_loop()` của `agent/loop.py`.

