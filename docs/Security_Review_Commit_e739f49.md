# Security Review Report: Commit `e739f49`

Tôi đã tiến hành kiểm tra (audit) toàn bộ các thay đổi trong commit `e739f49` (tác giả Tranquangkhai12) với tuyên bố *"Fix Backend and Ring3 Host security bugs (OWASP, IDOR, IPC, Memory Leaks, Kiosk)"*.

**Kết luận khẩn cấp**: Các bản vá này **KHÔNG** giải quyết triệt để vấn đề, phần lớn là mã đối phó, và thậm chí còn đưa thêm các lỗ hổng chí mạng (Critical) mới vào hệ thống, cho phép học sinh dễ dàng qua mặt bài thi.

Dưới đây là chi tiết các lỗi chí mạng vẫn còn hoặc mới xuất hiện trong bản cập nhật này:

---

## 1. Lỗi nghiêm trọng tại UI (React) - `src/Ring3_UserApp/ui/src/App.tsx`

> **Lưu ý:** Các thay đổi ở UI không những không khóa được Kiosk mà còn tặng không cho học sinh quyền mở khóa bài thi.

- **Bypass Kiosk (Đã bị comment out)**: Logic kiểm tra môi trường WebView2 (`window.chrome?.webview`) đã bị **comment out**. Học sinh có thể mở giao diện thi trên Chrome/Edge bình thường, bật DevTools (F12) và gian lận thoải mái.
- **Tự động mở khóa bài thi khi API lỗi**: Trong hàm `getConfig()`, logic catch lỗi API lại được gọi `setExamUnlocked(true)`! Học sinh chỉ cần ngắt mạng hoặc chặn API là giao diện sẽ tự động mở bài thi mà không cần giáo viên cho phép.
- **Lưu JWT Token không an toàn**: Hàm `handleLogout()` chỉ reset state của React mà **quên xóa** token trong `localStorage`. Token vẫn còn nguyên và có thể bị đánh cắp.

---

## 2. Lỗi nghiêm trọng tại Backend (`ExamBackend`)

> **Lưu ý:** Bản vá OWASP và IDOR hoàn toàn vô tác dụng do kiểm tra null sai logic.

- **Bypass ràng buộc phần cứng (HWID)**: Trong `AuthController.java`, logic kiểm tra HWID là: `if (user.getHwid() == null && authRequest.hwid != null && !authRequest.hwid.isEmpty())`. Nghĩa là nếu hacker cố tình gửi request login không có trường `hwid`, điều kiện này bị sai và Backend sẽ bỏ qua toàn bộ việc kiểm tra thiết bị, cho phép đăng nhập từ mọi máy!
- **Lỗ hổng IDOR vẫn còn nguyên**: Trong `ExamController.java`, kiểm tra quyền sở hữu bài thi được viết là: `if (session.getUser() != null) { ... check ... }`. Nếu hacker gửi một request mà `session.getUser()` bị ép thành `null` (do lỗi ORM hoặc dữ liệu rác), hệ thống sẽ bỏ qua bước check và tự động cho qua!
- **Exception Handler phá vỡ Security**: `GlobalExceptionHandler` bắt tất cả `Exception.class` và trả về HTTP 500. Điều này ghi đè lên các lỗi `AccessDeniedException` (HTTP 403) và `AuthenticationException` (HTTP 401) của Spring Security, khiến hệ thống báo lỗi server thay vì từ chối quyền truy cập.

---

## 3. Lỗi nghiêm trọng tại Ring 3 Host (C++)

> **Lưu ý:** Trình quét tiến trình (DynamicScanner) dễ dàng bị lừa bởi các chiêu trò đổi tên hoặc giả chữ ký cơ bản nhất.

- **Lỗ hổng TOCTOU & PID Reuse**: `DynamicScanner` lưu PID vào `m_scannedPids` và bỏ qua trong các lần quét sau. Nếu một tiến trình tắt đi và Windows tái sử dụng PID đó cho một phần mềm gian lận (cheat), phần mềm cheat sẽ hoàn toàn tàng hình vì PID đã nằm trong danh sách "đã quét".
- **Chấp nhận MỌI chữ ký số (Universal Certificate Acceptance)**: Hàm `VerifyDigitalSignature` chỉ kiểm tra xem file có chữ ký số (WinVerifyTrust) hay không, nhưng lại **không kiểm tra** đó là chứng chỉ của ai (Subject/Publisher) hay Root CA nào. Hacker chỉ cần tự tạo một chứng chỉ "rác" (Self-signed), ký vào tool Cheat của mình. Scanner sẽ báo đây là "File hợp lệ" (TRUSTED) và nhét tool Cheat thẳng vào Whitelist của Kernel Ring 0!
- **Spoofing Tên Tiến Trình System**: Các tiến trình được duyệt dựa trên tên (vd: `explorer.exe`, `svchost.exe`). Hacker chỉ cần đổi tên tool cheat thành `svchost.exe` và chạy từ Desktop, Scanner sẽ bỏ qua không quét.
- **Xóa PE Header gây lỗi**: Cơ chế tự bảo vệ bằng cách gọi `SecureZeroMemory` xóa `SizeOfHeaders` của chính nó sẽ làm hỏng các API hệ thống (GetModuleFileName, exception unwinding), gây crash ứng dụng ngẫu nhiên.
- **Check Hardware Breakpoint sai luồng (thread)**: Hàm kiểm tra Breakpoint cứng (Dr0-Dr3) chỉ gọi `GetThreadContext` trên chính cái luồng đang chạy ngầm của nó. Nếu hacker đặt Breakpoint lên luồng (thread) chính chứa giao diện UI, tính năng này hoàn toàn bị mù và không phát hiện được gì.
