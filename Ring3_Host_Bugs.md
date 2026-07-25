# Báo Cáo Lỗi Tầng Ring 3 (Client / Host App)

Tài liệu này tổng hợp toàn bộ các lỗi liên quan đến quản lý bộ nhớ, lỗ hổng tự bảo vệ và kiến trúc IPC trong ứng dụng C++ Host (`Ring3_UserApp`).

## 1. Lỗ Hổng Tự Bảo Vệ & Backdoor (Cực kỳ nghiêm trọng)

> [!CAUTION]
> Ứng dụng hiện tại đang tự vô hiệu hóa các cơ chế bảo vệ của chính nó, khiến toàn bộ nỗ lực ngăn chặn cheat trở nên vô nghĩa.

*   **Vô hiệu hóa việc tự tắt (Disabled Hard Termination)**:
    *   Trong `main.cpp`, hàm `OnIntegrityFail` đã bị comment out các dòng lệnh tắt chương trình (`// g_running = false; // PostQuitMessage(0);`).
    *   **Hậu quả**: Khi phát hiện Debugger, Cheat Engine, hay can thiệp RAM, ứng dụng chỉ báo lỗi lên UI nhưng... vẫn tiếp tục cho phép học sinh làm bài thi bình thường.
*   **Cửa hậu (Backdoor) thoát Kiosk Mode**:
    *   Trong `main.cpp`, tổ hợp phím `Ctrl + Q` được cài đặt để gọi thẳng `PostQuitMessage(0)`.
    *   **Hậu quả**: Học sinh có thể bấm phím này để tắt màn hình thi ngay lập tức, vượt qua cơ chế khóa màn hình.
*   **Tắt bảo mật của trình duyệt (WebView2)**:
    *   Truyền tham số `--disable-web-security` và `--disable-features=IsolateOrigins,site-per-process`.
    *   **Hậu quả**: Tắt Same-Origin Policy (SOP). Mở ra nguy cơ bảo mật web (XSS, v.v.) cực lớn nếu được đưa vào sử dụng thực tế.
*   **Bỏ qua các Check Quan Trọng**:
    *   Trong `IntegrityChecker.cpp`, hàm quét DLL injection (`HasUnknownModulesInjected`) và hàm xóa PE header (`ErasePEHeader`) bị comment out.

## 2. Lỗi Rò Rỉ Bộ Nhớ (Memory Leaks) & Quản lý Tài nguyên

> [!WARNING]
> Rò rỉ bộ nhớ sẽ làm ứng dụng tiêu thụ RAM tăng dần theo thời gian, dẫn đến sập ứng dụng (crash).

*   **Leak Memory khi gửi Message (`MessageBridge.cpp`)**:
    *   Khởi tạo con trỏ động bằng `new std::wstring(jsonPayload)` để gửi qua `PostMessageW`. Tuy nhiên, nếu `PostMessageW` trả về `FALSE` (do hàng đợi đầy hoặc window bị tắt), pointer này không bao giờ được `delete`.
*   **Phình to Array vô hạn (`DynamicScanner.cpp`)**:
    *   Lưu mọi thông tin tiến trình vào `m_history` và `m_scannedPids` nhưng không có cơ chế xóa bớt (pruning) hoặc giới hạn (cap).
    *   **Hậu quả**: RAM bị ăn mòn liên tục. Hơn nữa, Windows có cơ chế dùng lại PID (PID Recycling). PID cũ đã thoát nhưng vẫn nằm trong `m_scannedPids` sẽ làm cho tiến trình mới bị bỏ qua không được quét.
*   **Lỗi Vòng Đời Thread (Detached Threads)**:
    *   Các luồng background được tạo bằng `.detach()`.
    *   **Hậu quả**: Khi tắt ứng dụng, luồng chính giải phóng các biến toàn cục (Global) trong khi luồng phụ vẫn đang chạy, gây Use-After-Free và crash ngầm lúc thoát.

## 3. Lỗi Giao Tiếp (IPC) và UI

*   **Lỗi cấu hình Event Listener Buffer (`DriverController.cpp`)**:
    *   Hàm `ListenForEvent` truyền `nullptr` và size `0` cho Input Buffer của `IOCTL_AK_LISTEN_EVENT`. Kernel lại yêu cầu truyền vào struct chứa Session Token.
    *   **Hậu quả**: Kernel trả về lỗi `STATUS_INFO_LENGTH_MISMATCH` ngay lập tức. Tính năng nhận cảnh báo gian lận từ Kernel bị tê liệt hoàn toàn.
*   **Parse JSON nguy hiểm (`main.cpp`)**:
    *   Đang dùng các hàm `std::wstring::find` thủ công để bóc tách JSON thay vì dùng thư viện chuẩn (như `nlohmann/json`).
    *   **Hậu quả**: Nếu nhận được chuỗi JSON không đúng format mong đợi, các hàm `std::stoul` có thể văng exception làm crash ứng dụng.
*   **UI Request Mismatch (`ui/src/api`)**:
    *   Thiếu việc xử lý hủy yêu cầu HTTP (AbortController) trong các luồng Polling, có thể gây nghẽn mạng. Bridge Listener không được dọn dẹp (cleanup) khi re-render.

## 4. Lỗi Build Script

*   **Đường dẫn cứng (Hardcoded Path)**:
    *   File `build.ps1` hardcode đường dẫn `$WorkingDir = "C:\Users\Asus\Atch_Kernel\src\Ring3_UserApp"`. File sẽ bị lỗi ngay lập tức khi chạy trên các máy khác (như máy của user hiện tại `Nguye`).
