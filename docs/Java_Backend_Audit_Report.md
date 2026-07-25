# Báo cáo Kiểm toán Bảo mật: Java Backend (`ExamBackend`)

**Ngày**: 25 tháng 7, 2026

## Các Lỗi Phát Hiện

- **Xác thực & Quản lý Bí mật**:
  - **Lộ Bí mật**: Khóa mã hóa JWT (JWT signing key) và mật khẩu gốc của cơ sở dữ liệu (`123456`) bị gắn cứng (hardcode) trong source code và file properties.
  - **Mật khẩu không được Hash (MỚI)**: `AdminController` lưu trực tiếp mật khẩu gốc mà không qua hàm băm `BCryptPasswordEncoder` khi tạo tài khoản người dùng mới.
  - **Thời gian hết hạn Token quá dài**: Token JWT có hiệu lực lên tới 10 tiếng mà không hề có cơ chế thu hồi (revocation) hay danh sách đen (blacklist).
- **Lỗ hổng Logic Nghiệp vụ (ExamController)**:
  - **IDOR / Kiểm soát truy cập hỏng**: Đoạn code `auth != null` bị lỗi logic, bỏ qua bước kiểm tra quyền sở hữu, cho phép người dùng chưa xác thực có thể nộp (submit) kết quả thi cho bất kỳ phiên thi nào.
  - **Không ràng buộc Trạng thái**: Có thể nộp bài thi nhiều lần dù trạng thái bài thi đã là `COMPLETED` (đã hoàn thành).
  - **Ràng buộc Thời gian không đầy đủ**: Chỉ bắt buộc thời gian tối thiểu (< 1 phút) nhưng lại không kiểm tra giới hạn thời gian tối đa làm bài.
  - **Thiếu kiểm tra Dữ liệu**: Dữ liệu `submissionData` bị bỏ qua hoàn toàn và không được lưu vào cơ sở dữ liệu.
- **Chiếm đoạt Hardware ID (HWID) (Mức độ Nghiêm trọng)**:
  - **Tự động gán HWID (Auto-binding Hijack)**: Lần đăng nhập đầu tiên sẽ âm thầm gán HWID của máy hiện tại cho tài khoản mà không có bước xác minh. Điều này cho phép kẻ tấn công đăng nhập trước và vĩnh viễn khóa tài khoản sinh viên vào thiết bị của kẻ đó.
  - Kiểm tra HWID CHỈ được áp dụng trong lúc đăng nhập. Các API khác sau khi đăng nhập (như submit) không kiểm tra lại HWID, cho phép kẻ trộm token có thể vượt qua lớp bảo vệ thiết bị hoàn toàn.
- **Cấu hình Session & CORS sai lệch**:
  - **Session có trạng thái (Stateful)**: Cấu hình sử dụng `SessionCreationPolicy.IF_REQUIRED` bị sai do API đã dùng cơ chế bộ lọc JWT không trạng thái (stateless).
  - **CORS quá lỏng lẻo**: Allowed origins và headers được thiết lập thành dấu sao `*` (cho phép tất cả).
- **Thiếu API Ghi nhận Gian lận (Anti-Cheat)**: Route `POST /api/security-logs` không hề tồn tại, dẫn đến các cảnh báo vi phạm từ phía máy trạm (client host) bị bỏ qua âm thầm (lỗi 404).
- **Thiếu Giới hạn Băng thông (Rate Limiting)**: Không có cơ chế chống request liên tục ở các API công khai (`/api/auth/login`), khiến hệ thống phơi mình trước các cuộc tấn công dò mật khẩu (brute-force).
- **Thư viện phụ thuộc dính Lỗ hổng**: Sử dụng `spring-boot-starter-parent 3.3.1` hiện đang có lỗ hổng Path Traversal đang bị khai thác thực tế (yêu cầu cập nhật lên `3.3.6+`).
- **Xử lý Ngoại lệ (Exception Handling)**: Bỏ qua (swallow) các Exception chung chung, trả về cấu trúc lỗi không đồng nhất, và thiếu bao quát xử lý lỗi toàn cục `GlobalExceptionHandler`.
