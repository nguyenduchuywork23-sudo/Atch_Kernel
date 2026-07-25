# Báo cáo Kiểm toán Bảo mật: Ring 3 C++ Host Application (Ứng dụng Máy chủ)

**Ngày**: 25 tháng 7, 2026

## Các Lỗi Phát Hiện

- **Token Phiên bản (Session) Bị Hardcode**: Token phiên bản được gắn cứng trong code (`kSessionToken = L"ATCH_SESSION_2026_XYZ"`) thay vì được cấp phát động từ server backend. Đây là rủi ro bảo mật rất nghiêm trọng.
- **Lỗi Xử lý Vòng lặp Sự kiện & UI**: `OnIntegrityFail` và `OnHeartbeatFail` gọi `PostQuitMessage(0)` từ các luồng chạy ngầm (background threads) thay vì luồng UI chính, khiến cửa sổ bài thi không thể đóng lại khi phát hiện vi phạm.
- **Treo máy (Deadlock) khi Hủy Luồng**: Trong quá trình tắt ứng dụng, `ListenForEvent` vẫn bị kẹt (block) ở tầng kernel trong khi `WinMain` cố gắng gộp (join) các luồng ngầm, gây ra tình trạng treo vô thời hạn.
- **Vượt rào (Bypass) Kiểm tra Bảo mật**:
  - Việc xóa trắng Header PE (PE Header zeroing) đang bị vô hiệu hóa / comment lại trong `IntegrityChecker.cpp` (hàm `SecureZeroMemory` không hoạt động).
  - Kiểm tra đường dẫn tiến trình cha lỏng lẻo (chỉ kiểm tra tên file, không kiểm tra đường dẫn tuyệt đối đầy đủ).
- **Cảnh báo Nhầm (False Positives)**:
  - Kiểm tra máy ảo bằng `CPUID` đánh dấu tính năng VBS/Hyper-V bản địa của Windows là mã độc, gây ra việc khóa nhầm người dùng hợp lệ trên Windows 11.
  - Các cuộc tấn công thời gian `RDTSC` thô sơ kích hoạt cảnh báo nhầm do quá trình chuyển đổi ngữ cảnh (context switch) thông thường của hệ điều hành.
  - Việc đưa các file thực thi không có chữ ký số vào danh sách đen (blacklist) toàn hệ thống chặn cả những tiện ích vô hại một cách quá mức.
- **Vấn đề Bộ nhớ/Hiệu năng**: Việc dọn dẹp bộ nhớ đệm tiến trình (process cache) mỗi 4 phút gây ra giật lag CPU/Disk I/O nghiêm trọng, trong khi vector `m_history` gây rò rỉ bộ nhớ vô thời hạn.
- **Bảo mật IPC & Webview**:
  - Việc phân tích cú pháp JSON bằng tay, không có escape ký tự (`json.find` và `std::stoul`) trong `HandleReactMessage` khiến ứng dụng có nguy cơ bị crash hoặc chèn mã (injection).
  - Kiểm tra tên miền (domain) lỏng lẻo cho phép `http://attacker-localhost.com` vượt qua các giới hạn của WebView2.
  - Việc liên tục xóa bộ nhớ tạm (clipboard) toàn cục mỗi 3 giây làm ảnh hưởng đến trải nghiệm người dùng.
