# KẾ HOẠCH PHÁT TRIỂN DÀI HẠN - HỆ THỐNG ATCH KERNEL

Tài liệu này đóng vai trò là "kim chỉ nam" cho toàn bộ vòng đời phát triển dự án Atch Kernel. Kiến trúc hệ thống được chia làm ba phân hệ rõ ràng để phân rã trách nhiệm. Dưới đây là quy hoạch công việc:

---

## PHẦN A. TRÁCH NHIỆM CỦA NGUYỄN ĐỨC HUY (RING 0 & THE BRIDGE)

Là kiến trúc sư trưởng Hệ thống cấp thấp, bạn chịu trách nhiệm thiết kế, lập trình và bảo vệ toàn bộ cấu trúc lõi của phần mềm thi:

### 1. Tầng Nhân (Ring 0) - Core Driver
- **Phòng thủ Chủ động (Enforcement Callbacks)**:
  - **Tiến trình (`PsSetCreateProcessNotifyRoutineEx`)**: Bắt và chặn mọi tiến trình/công cụ hack trái phép từ lúc khởi chạy.
  - **Registry (`CmRegisterCallbackEx`)**: Khóa các nhánh Registry nhạy cảm, chống kỹ thuật gián điệp và Debugger Injection (IFEO).
  - **Tự vệ hệ thống (`ObRegisterCallbacks`)**: Tự động tước bỏ quyền truy cập sâu (`PROCESS_TERMINATE`, `PROCESS_VM_WRITE/READ`) nếu phát hiện ai đó cố tình đóng hoặc sửa bộ nhớ phần mềm thi.
  - **Anti-DKOM & Page Tables**: Ngăn chặn Rootkit bằng cách giám sát chéo EPROCESS và thanh ghi CR3.
- **Quản lý Hiệu năng & BSOD**:
  - Quản lý đồng bộ chặt chẽ: `Fast Mutex` cho `PASSIVE_LEVEL` và `SpinLock` cho `DISPATCH_LEVEL`.
  - Cấp phát bộ nhớ không thực thi (NonPagedPoolNx) để tránh tấn công chèn mã.

### 2. Tầng Giao Tiếp (The Bridge)
- **Thiết lập Kênh truyền (IPC Backbone)**: Quản lý thiết bị (`IoCreateDevice`) và liên kết tượng trưng (`SymbolicLink`) để Ring 3 có thể gửi `DeviceIoControl`.
- **Kiểm soát tính hợp lệ (Input Validation)**: Mọi gói tin (`METHOD_BUFFERED`) đều bị kiểm tra kích thước đệm nghiêm ngặt nhằm tránh tràn bộ đệm cấp nhân.
- **Cơ chế Gọi ngược (Inverted Call Mechanism)**:
  - Khởi tạo hàng đợi IRP an toàn (WDFQUEUE).
  - Treo (Pending) lệnh yêu cầu từ Ring 3 thay vì để Ring 3 gọi Ping liên tục.
  - Ngay khi các Callback (Tiến trình/Registry) tóm được vi phạm, truyền ngược gói tin báo động về thẳng luồng Overlapped I/O của Ring 3 để đóng bài thi ngay lập tức (< 1ms).

---

## PHẦN B. TRÁCH NHIỆM CỦA CỘNG SỰ TEAM (RING 3 - USER APP)

*Lưu ý: Bạn (Huy) không cần tham gia viết code cho phần này, đây là checklist dành cho Team Cộng sự ghép nối:*

### 3. Tầng Ứng dụng & Mạng
- **Giao diện & Trình duyệt**: Thiết kế UI (C++/Qt hoặc C#), nhúng Webview2 tải nội dung đề thi.
- **Môi trường Cách ly (Secure Desktop)**: 
  - Gọi API `CreateDesktop` / `SwitchDesktop` để đưa thí sinh vào vùng không gian kín.
  - Chặn triệt để phím tắt hệ thống (Alt+Tab, Taskmgr, Windows Key).
- **Giao tiếp với Driver của Huy**:
  - Bắt tay (Handshake): Xác thực bằng định danh phiên bản.
  - Gửi nhịp đập (Heartbeat) định kỳ 1000ms.
  - Treo luồng chờ tín hiệu Inverted Call từ Driver.
- **AI & Bảo vệ Mạng**:
  - Camera tracking gian lận cục bộ bằng AI.
  - Mã hóa E2E giao thức với máy chủ đại học.

---

## 4. KẾ HOẠCH KIỂM THỬ (TEST MATRIX) DÀNH CHUNG CHO 2 ĐỘI
- **Test_01 (Giao tiếp Ping/Pong)**: Kiểm tra thông luồng The Bridge. Độ trễ yêu cầu < 0.1ms.
- **Test_02 (Fail-Safe)**: Cố tình làm crash ứng dụng Ring 3 (bên Cộng sự) để xem Ring 0 (bên Huy) có tự dọn dẹp các IRP Pending và tránh BSOD hay không.
- **Test_03 (Anti-Tampering)**: Dùng Process Hacker/Cheat Engine tấn công từ Ring 3 -> Driver Ring 0 phải vô hiệu hóa quyền.
- **Test_04 (IOCTL Fuzzing)**: Bắn hàng ngàn gói tin rác xuống Driver -> Ring 0 phải chặn tràn bộ đệm.

---

## 5. MỤC TIÊU PHÁT HÀNH (PRODUCTION DEPLOYMENT)
Khi triển khai ra máy tính sinh viên, Driver của bạn (Huy) sẽ cần:
1. **HVCI (Core Isolation)**: Phải tương thích hoàn toàn tính năng ảo hóa bảo mật của Windows 11.
2. **Ký số thương mại (Code Signing)**: Driver phải được ký EV Certificate để vượt rào Windows.
3. **Microsoft WHQL**: Thông qua kiểm duyệt chất lượng cấp cao nhất từ Microsoft.
