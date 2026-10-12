# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản:
  Gitleaks phiên bản v8.30.1.

- Commit chứa token giả:
  Commit `1bdd849` (mã băm đầy đủ: `1bdd849922156c868a5ee9293d68f5b72e242d2c`).

- File, rule và kết quả quét lịch sử:
  - File bị lộ: `lab-fake-secret.txt` (dòng 1).
  - Rule phát hiện: `lab24-synthetic-token` (rule được định nghĩa trong `.gitleaks.toml`).
  - Kết quả quét: Lệnh `gitleaks git --config .gitleaks.toml --redact --verbose .` quét 9 commit trong lịch sử và tìm thấy 1 finding chứa token giả phục vụ diễn tập (exit code 1). Đây là dữ liệu synthetic của bài lab, không phải sự cố bảo mật thật.

- Kết quả quét file hiện tại:
  - Lệnh `gitleaks dir --config .gitleaks.toml .` quét thư mục hiện tại báo cáo `no leaks found` (exit code 0), xác nhận file chứa token đã được xóa khỏi HEAD.
  - Hook `pre-commit run --all-files` với `gitleaks-system` vượt qua kiểm tra thành công (Passed).

- Nếu đây là credential thật, cần xử lý thế nào:
  - Ngay lập tức phải thực hiện **thu hồi (revoke) và rotate (đổi khóa)** token trực tiếp tại hệ thống / nhà cung cấp dịch vụ để vô hiệu hóa giá trị của nó.
  - Kiểm tra access log / audit log của dịch vụ tương ứng để đánh giá xem credential này đã bị kẻ xấu khai thác trong thời gian lộ hay chưa.
  - Làm sạch lịch sử Git bằng `git filter-repo` hoặc BFG Repo-Cleaner rồi force push lại repo.
  - Cập nhật credential mới an toàn vào trình quản lý bí mật (secret manager / environment variables), tuyệt đối không lưu cứng trong code.

- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Việc chỉ xóa file khỏi HEAD ở commit sau thực chất chỉ ẩn file khỏi nhánh hiện tại. Trong Git, commit cũ `1bdd849` vẫn được lưu trữ nguyên vẹn trong lịch sử commit, bất kỳ ai có quyền truy cập repo đều có thể checkout commit cũ hoặc dùng Git log để đọc được secret.
  - Pin dependency và pre-commit hook chỉ là cơ chế phòng vệ nhằm ngăn chặn phụ thuộc bị can thiệp và ngăn việc commit nhầm trong tương lai. Chúng hoàn toàn không có tác dụng làm mất hiệu lực của một credential đã bị lộ ra ngoài. Vì vậy, chỉ có bước **thu hồi và rotate** secret từ phía hệ thống mới đảm bảo an toàn thực sự.

