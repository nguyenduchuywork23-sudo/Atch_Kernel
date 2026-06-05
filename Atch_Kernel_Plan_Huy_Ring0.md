# KẾ HOẠCH PHÁT TRIỂN - PHÂN HỆ RING 0 & THE BRIDGE

**Người phụ trách:** Nguyễn Đức Huy (System Architect)  
**Công nghệ:** C++ / KMDF (WDF)

Là kiến trúc sư trưởng Hệ thống cấp thấp, tài liệu này thống kê toàn bộ trách nhiệm thiết kế, lập trình và bảo vệ cấu trúc lõi của phần mềm thi dành riêng cho bạn.

---

## 1. Tầng Nhân (Ring 0) - Core Driver
- **Phòng thủ Chủ động (Enforcement Callbacks)**:
  - **Tiến trình (`PsSetCreateProcessNotifyRoutineEx`)**: Bắt và chặn mọi tiến trình/công cụ hack trái phép từ lúc khởi chạy dựa trên Blacklist/Whitelist.
  - **Registry (`CmRegisterCallbackEx`)**: Khóa các nhánh Registry nhạy cảm, chống kỹ thuật gián điệp và Debugger Injection (đặc biệt là Image File Execution Options - IFEO).
  - **Tự vệ hệ thống (`ObRegisterCallbacks`)**: Tự động tước bỏ quyền truy cập sâu (`PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, `PROCESS_VM_READ`) nếu phát hiện tiến trình lạ cố tình đóng hoặc can thiệp vào không gian bộ nhớ của phần mềm thi.
  - **Anti-DKOM & Page Tables**: Ngăn chặn Rootkit bằng cách giám sát chéo EPROCESS và thanh ghi CR3, bảo vệ Page Table Entries (PTE).
- **Quản lý Hiệu năng & Ổn định (Zero BSOD Policy)**:
  - Quản lý đồng bộ chặt chẽ: Dùng `Fast Mutex` khi IRQL ở mức `PASSIVE_LEVEL` và dùng `SpinLock` khi IRQL ở mức `DISPATCH_LEVEL`. Tránh Deadlock.
  - Cấp phát vùng nhớ không thực thi (`NonPagedPoolNx`) để bảo vệ dữ liệu nội bộ (như Whitelist) khỏi các lỗ hổng chèn mã độc.

## 2. Tầng Giao Tiếp (The Bridge)
- **Thiết lập Kênh truyền (IPC Backbone)**: Khởi tạo Device Object (`IoCreateDevice`) và liên kết tượng trưng (`SymbolicLink`) để Ring 3 có thể gửi lệnh `DeviceIoControl`.
- **Kiểm soát tính hợp lệ (Input Validation)**: Mọi gói tin truyền qua `METHOD_BUFFERED` đều bị kiểm tra kích thước đệm nghiêm ngặt nhằm tránh tràn bộ đệm cấp nhân (Buffer Overflow).
- **Cơ chế Gọi ngược (Inverted Call Mechanism)**:
  - Xây dựng một hàng đợi IRP an toàn (WDFQUEUE).
  - Khóa và Treo (Pending) các request lắng nghe sự kiện từ Ring 3 thay vì để Client gọi Ping liên tục gây tốn CPU.
  - Ngay khi các Callback bảo vệ (ở Ring 0) phát hiện vi phạm, Driver sẽ nạp dữ liệu lỗi vào gói IRP đang treo và trả về thẳng cho Ring 3 (`WdfRequestComplete`) để đóng bài thi ngay lập tức (< 1ms).

---

## 3. Kế hoạch Kiểm thử (Test Matrix)
- **Test_01 (Giao tiếp Ping/Pong)**: Kiểm tra tính thông suốt của The Bridge, đảm bảo Driver nhận và phản hồi I/O đồng bộ với độ trễ < 0.1ms.
- **Test_02 (Fail-Safe)**: Phối hợp giả lập Ring 3 crash đột ngột -> Driver phải dọn dẹp an toàn các IRP Pending và handle cuối cùng, không gây BSOD.
- **Test_03 (Anti-Tampering)**: Dùng Process Hacker/Cheat Engine (cấp quyền SYSTEM) cố gắng Kill Process của ứng dụng thi -> Driver phải vô hiệu hóa thành công quyền truy cập này.
- **Test_04 (IOCTL Fuzzing)**: Bắn hàng ngàn gói tin rác/dị dạng xuống Driver -> Kiểm tra mức độ chịu đựng ngoại lệ (SEH) và khả năng bắt lỗi bộ đệm của mã nguồn Kernel.

## 4. Mục tiêu Phát hành (Production Deployment)
Khi gói Driver để đưa vào máy tính của sinh viên:
1. **HVCI (Core Isolation)**: Code Driver phải đạt chuẩn an toàn vùng nhớ (memory-safe), tương thích hoàn toàn tính năng ảo hóa bảo mật của Windows 11.
2. **Ký số thương mại (Code Signing)**: Driver phải được ký bằng chứng thư số Extended Validation (EV Certificate).
3. **Microsoft WHQL**: Đệ trình qua cổng Microsoft Hardware Dev Center để nhận chứng nhận WHQL hợp lệ cho Windows 10/11.
