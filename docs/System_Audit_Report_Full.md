# Báo Cáo Tổng Kiểm Tra Toàn Bộ Hệ Thống (System Audit Report)
**Ngày thực hiện**: 25/07/2026
**Phạm vi**: Ring 0 Kernel Driver, Ring 3 C++ Host, React UI Frontend
**Thực hiện bởi**: Đội ngũ Subagents

Dưới đây là tổng hợp chi tiết các lỗ hổng, lỗi logic, lỗi bộ nhớ và các rủi ro bảo mật nghiêm trọng được phát hiện sau khi kiểm tra toàn bộ hệ thống.

---

## 1. Phân Hệ Ring 0 Kernel Driver (`src/Ring0_CoreDriver`)

### 1.1 Lỗ Hổng Logic & Bảo Vệ Registry
- **Bypass Rate Limiter**: Kiểm tra Rate Limiter nằm trước kiểm tra bảo vệ, cho phép kẻ tấn công flood request để bypass bảo vệ Registry.
- **Lỗi So Sánh Đường Dẫn**: Xử lý sai đường dẫn tương đối (chưa chuẩn hóa dấu `/` và `\`), cho phép kẻ tấn công dùng đường dẫn khác để xóa key của driver.
- **Bỏ Sót APIs**: Không kiểm tra `RegNtPreCreateKeyEx`, `RegNtPreSetKeySecurity` khi kỳ thi không hoạt động, tạo kẽ hở sửa ACL.
- **Lọc Bigram Sai Lệch**: Hàm `FastRegistryPreFilter` có thể trả về false negative nếu không chứa các bigram cứng.

### 1.2 Lỗi Quản Lý Bộ Nhớ & Object (Handle/Reference Leaks)
- **Use-After-Free (UAF) trên `g_ClientEProcess`**: Pointer được lưu giữ và truy cập lock-free trong `ObRegisterCallbacks`, dẫn tới màn hình xanh (BSOD) nếu tiến trình bị hủy đột ngột.
- **Work Item Storm**: Khi tiến trình chết, hàm fallback `PsLookupProcessByProcessId` liên tục thất bại tạo ra hàng trăm Work Item làm treo hàng đợi.
- **Rò rỉ Reference (Leak)**: Cán cân đếm reference (`ObReferenceObject`) trên `PEPROCESS` và `PKTHREAD` bị rò rỉ trong các trường hợp lỗi khởi tạo Thread Heartbeat hoặc khi hoán đổi `g_ClientEProcess`.

### 1.3 Lỗi Đồng Bộ Hóa (Synchronization & Race Conditions)
- **Double-Free PnP & InputBlocker**: Xung đột giữa `UninitializeInputBlocker` và `IRP_MN_REMOVE_DEVICE` khi rút thiết bị (chuột/phím), gây BSOD.
- **Data Race trên `g_SessionTokenStore`**: Đọc không khóa (lock-free) token khi một luồng khác đang ghi hoặc xóa token.
- **Race Condition Lock/Unlock**: Lệnh `UnlockExam` từ Ring 3 có thể ghi đè (override) cờ vi phạm bảo mật từ các luồng callback dưới Kernel.

---

## 2. Phân Hệ Ring 3 C++ Host (`src/Ring3_UserApp/host`)

### 2.1 Quản Lý Bộ Nhớ & Tối Ưu Hiệu Suất (Memory & Leaks)
- **Rò Rỉ Bộ Nhớ Cực Lớn (`m_history`)**: `DynamicScanner` lưu liên tục mọi lịch sử tiến trình mà không có giới hạn, gây tràn RAM sau thời gian dài.
- **Cache Thrashing**: Xóa sạch `m_scannedPids` mỗi 4 phút khiến hệ thống phải hash và verify chứng chỉ lại từ đầu, gây 100% Disk/CPU usage.
- **WinVerifyTrust Network Blocking**: Kiểm tra thu hồi chứng chỉ đồng bộ gây kẹt (hang) luồng quét nếu mạng yếu.
- **Rò Rỉ Heap (WM_POST_TO_REACT)**: Payload JSON bị bỏ quên trên Heap nếu cửa sổ tắt trước khi Windows xử lý hết hàng đợi Message.

### 2.2 Lỗi Đa Luồng & Deadlock (Thread Safety)
- **Deadlock Khi Thoát**: Hàm `ListenForEvent` gọi IOCTL đồng bộ (blocking). Khi thoát, UI Thread chờ `join()` luồng này nhưng luồng này lại đang bị kẹt ở Kernel.
- **Dùng Sai `PostQuitMessage(0)`**: Gọi trên luồng chạy ngầm (Heartbeat, Integrity) khiến thông báo bị mất, giao diện UI biến thành Zombie không tắt được.
- **Xung Đột Handle (`m_hDevice`)**: Đóng Handle ở luồng chính khi luồng phụ đang gửi IOCTL, gây lỗi Use-After-Close.
- **Lỗi Khởi Tạo COM**: Hủy COM (`CoUninitialize`) trước khi dọn dẹp các luồng nền.

### 2.3 Lỗ Hổng Bảo Mật & Xác Thực (Security & Cryptography)
- **Dùng CRC32 Thay Vì Crypto Hash**: Kiểm tra tính toàn vẹn của file thực thi bằng CRC32 - cực kỳ dễ bị làm giả.
- **Session Token Hardcode**: Chuỗi token `ATCH_SESSION_2026_XYZ` bị gắn cứng, dễ dàng bị dịch ngược.
- **Quá Tin Tưởng Chữ Ký Số**: Chỉ cần có chữ ký số hợp lệ (kể cả tự tạo) là phần mềm được đưa vào Whitelist ở Kernel.
- **Unauthenticated IPC**: WebView2 không xác thực Message, mã độc XSS dễ dàng gửi lệnh mở khóa (UNLOCK) xuống C++.

### 2.4 Lỗi Ngoại Lệ & Null Pointer
- **Null Pointer Dereferences**: Không kiểm tra con trỏ Null khi khởi tạo WebView2 COM, `KBDLLHOOKSTRUCT`, và phân tích PE Header.
- **Lỗi chuỗi JSON**: Đường dẫn thư mục Windows (`C:\Windows\...`) không được escape `\` khiến `JSON.parse` bên React văng lỗi.

---

## 3. Phân Hệ React UI Frontend (`src/Ring3_UserApp/ui`)

### 3.1 Vấn Đề Xác Thực & Dữ Liệu
- **Lưu JWT trong `localStorage`**: Dễ bị tấn công XSS trộm Token. Token không tự xóa khi người dùng tắt app mà không ấn Đăng xuất.
- **Console Logs Leak**: In toàn bộ `sessionToken`, `sha256` của phần mềm, và cấu trúc API nội bộ ra Console, kể cả trên môi trường Production.
- **Bypass IPC Origin**: Lắng nghe `postMessage` nhưng không kiểm tra cờ `event.origin` và dùng target origin là `*`.

### 3.2 Race Conditions Trong React Hooks
- **Chia sẻ `AbortController`**: Hàm Polling dùng chung một `AbortController`, dẫn tới việc response cũ ghi đè dữ liệu mới nếu mạng chập chờn.
- **Nộp Bài Trùng Lặp**: Nhấn nhanh nút Nộp bài hoặc đồng hồ đếm ngược hết giờ trùng lúc click sẽ gây ra 2 request submit đồng thời.
- **Unmounted State Update**: Polling `getConfig` không kiểm tra vòng đời Component, gây lỗi bộ nhớ rò rỉ (memory leak warning) trong React.

### 3.3 Khuyết Điểm Xử Lý Lỗi (Improper Error Handling)
- **Vòng lặp nộp bài vô tận**: Khi mạng lỗi, chức năng auto-submit sẽ gọi nộp bài thất bại liên tục và pop-up alert không ngừng nghỉ.
- **Màn hình trắng (White Screen)**: Thiếu `ErrorBoundary` toàn cục, nếu có lỗi runtime render thì toàn bộ màn hình Kiosk biến thành màu trắng, thí sinh kẹt vĩnh viễn.
- **Thao tác DOM trực tiếp**: `document.body.innerHTML` dùng trong `useEffect` gây xung đột với Virtual DOM của React.
- **Bỏ qua lỗi Backend**: Các lời gọi `postSecurityLog` khi dính lỗi mạng bị bỏ qua (swallowed), log gian lận không được gửi lại (retry) lên Server.
