# Báo cáo Kiểm toán Bảo mật: React Frontend UI (Giao diện Người dùng)

**Ngày**: 25 tháng 7, 2026

## Các Lỗi Phát Hiện

- **Lộ Bí mật (Hardcoded Secrets)**: Token dự phòng `'EXAM_2026_XYZ'` bị gắn cứng (hardcode) trong code, tạo nguy cơ bypass quá trình xác thực.
- **Lỗ hổng XSS & Iframe**:
  - Đường dẫn `src` của `<iframe>` động không được làm sạch (unsanitized), tạo rủi ro DOM-based XSS (ví dụ: chèn `javascript:...`).
  - Thiếu các thuộc tính `sandbox` và `referrerPolicy` trên iframe hiển thị đề thi.
  - Cấu hình phía Admin cho phép lưu trữ URL đích (target URL) mà không qua kiểm tra/xác thực.
- **Lỗ hổng IPC / Message Bridge**:
  - Gửi tin nhắn (broadcast) với target origin là dấu sao (`postMessage('*')`) tới toàn bộ các origin.
  - Thiếu việc kiểm tra nguồn gốc tin nhắn (`event.origin`), cho phép giả mạo các tin nhắn từ host (ví dụ: giả mạo `VIOLATION_DETECTED`).
  - Các payload IPC chứa token nhạy cảm bị in ra console (console.log).
- **Lưu trữ Token & Bảo mật**:
  - Lưu trữ JWT access token không an toàn trong `localStorage`.
  - Thiếu cơ chế vô hiệu hóa token (token vẫn tồn tại sau khi nhận phản hồi 401/403).
  - Làm lộ thông tin đăng nhập mặc định qua các gợi ý trên form UI.
- **Thư viện phụ thuộc**: Các thư viện React, Vite, và TypeScript đã lỗi thời và cần được vá lỗi cập nhật.
