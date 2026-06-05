# KẾ HOẠCH PHÁT TRIỂN - PHÂN HỆ RING 3 (USER APP)

**Người phụ trách:** Cộng sự Team  
**Công nghệ:** C++/Qt hoặc C#, Webview2, AI SDK

Tài liệu này bao gồm danh sách các yêu cầu kiến trúc và luồng xử lý ứng dụng dành riêng cho phần mềm Client chạy trên User Mode, nhằm đảm bảo phối hợp trơn tru với bảo mật lõi ở Ring 0.

---

## 1. Giao diện & Trình duyệt Thi
- **Phát triển UI**: Thiết kế giao diện phần mềm thi bằng C++/Qt hoặc C# (WPF/WinForms).
- **Core Trình duyệt**: Nhúng lõi **Webview2** để kết nối với nền tảng thi trực tuyến của trường đại học.
- **Tự bảo vệ UI (Anti-Screen Capture)**: Đảm bảo giao diện chặn được các công cụ chụp/quay màn hình thứ ba (thông qua cờ chống chụp màn hình của Windows API nếu có thể).

## 2. Môi trường Cách ly (Secure Desktop)
- **Tạo không gian vô trùng**: Sử dụng API `CreateDesktop` tạo ra một màn hình ảo mới tinh không chứa các Shortcut, Taskbar hay System Tray.
- **Ép buộc không gian thi**: Dùng API `SwitchDesktop` để đẩy ứng dụng và tầm nhìn của thí sinh vào màn hình ảo này.
- **Chặn phím tắt cấp cao**: Thực hiện hook/bắt các tổ hợp phím can thiệp hệ thống như Windows Key, Alt+Tab, Taskmgr.

## 3. Giao tiếp với Driver (Client -> The Bridge)
- **Bắt tay (Handshake) & Khởi tạo**: 
  - Mở handle `CreateFile` tới thiết bị `\\.\AtchKernel`.
  - Gửi mã Token và cấu hình xuống Driver (thông qua IOCTL).
- **Kênh Nhịp đập (Heartbeat)**: 
  - Khởi chạy tiểu trình chạy ngầm gửi IOCTL ping xuống Driver mỗi 1000ms.
  - Nếu mất Heartbeat, phải có logic tự khóa máy hoặc thông báo lỗi giả lập.
- **Lắng nghe Cảnh báo (Inverted Call)**:
  - Gửi IOCTL chuyên dụng tới Driver qua cơ chế Overlapped I/O.
  - Treo luồng chờ tín hiệu. Khi có vi phạm hệ thống (Tiến trình lạ/Sửa Registry), Driver sẽ hoàn thành IOCTL này. Phần mềm Client phải ngay lập tức khóa bài thi và thu thập thông tin gỡ lỗi.

## 4. AI Local & Hệ thống Mạng
- **Giám sát trực tiếp (Local AI Tracking)**: Tích hợp SDK AI nhận diện khuôn mặt và hành vi qua webcam ngay tại máy (tránh phụ thuộc băng thông server).
- **Đồng bộ Server**: Mã hóa End-to-End toàn bộ dữ liệu làm bài, nhật ký vi phạm (được Kernel báo lên) và hình ảnh webcam, chuyển về máy chủ giám thị.

---

## 5. Kế hoạch Phối hợp Kiểm thử (Test Matrix)
- **Test Fail-Safe**: Chủ động giả lập crash ở Ring 3 (throw exception đột ngột) để kiểm tra xem Ring 0 có bị dính Deadlock hay BSOD hay không.
- **Test Inverted Call**: Chạy giả lập một phần mềm bị cấm (như CheatEngine) để xem tín hiệu khóa bài từ Kernel có bắn lên Ring 3 đủ nhanh không (< 1ms).
- **Test Tấn công (Red Teaming)**: Đội Ring 3 cố gắng thử mọi cách vượt rào Secure Desktop và dùng quyền Administrator tắt tiến trình của chính mình để test độ cứng của Ring 0.
