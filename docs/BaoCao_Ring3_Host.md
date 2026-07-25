# Báo Cáo Bảo Mật — Ring 3 C++ Host Application

**Ngày**: 25/07/2026  
**Phạm vi**: `src/Ring3_UserApp/host/`  
**Lưu ý**: Đây là báo cáo chỉ-đọc, KHÔNG thực hiện sửa code.

---

## 🔴 Lỗi Nghiêm Trọng (Critical)

### 1. Hardcoded Session Token
- **File**: `src/Ring3_UserApp/host/src/main.cpp`
- **Mô tả**: Token phiên `ATCH_SESSION_2026_XYZ` được ghi cứng trong code thay vì lấy từ backend.
- **Rủi ro**: Bất kỳ ai đọc được mã nguồn hoặc dịch ngược (reverse engineering) đều có thể dùng token này để bypass xác thực.

### 2. WebView2 Whitelist Bypass
- **File**: `src/Ring3_UserApp/host/src/main.cpp`
- **Mô tả**: Logic whitelist dùng `std::wstring::find` (prefix matching) cho phép domain giả mạo vượt qua kiểm tra (VD: `localhost:5173.attacker.com`).
- **Rủi ro**: Attacker có thể load trang web tùy ý trong WebView2, phá vỡ sandbox.

### 3. `PostQuitMessage` từ Background Thread
- **File**: `src/Ring3_UserApp/host/src/main.cpp`
- **Mô tả**: `OnIntegrityFail` và `OnHeartbeatFail` gọi `PostQuitMessage(0)` từ thread nền thay vì UI thread chính.
- **Rủi ro**: Message pump không nhận được quit message → cửa sổ thi không đóng khi phát hiện vi phạm.

---

## 🟠 Lỗi Trung Bình (Medium)

### 4. `ErasePEHeader` phá vỡ `CheckIATIntegrity`
- **File**: `src/Ring3_UserApp/host/src/IntegrityChecker.cpp`
- **Mô tả**: `ErasePEHeader` xóa PE header (DOS/NT/Section headers) nhưng `CheckIATIntegrity` cần đọc chính các header này. Hiện tại `SecureZeroMemory` bị comment out nhưng nếu enable sẽ crash.
- **Khuyến nghị**: Cache IAT info TRƯỚC khi xóa PE header.

### 5. CPUID VM Detection False Positive
- **File**: `src/Ring3_UserApp/host/src/IntegrityChecker.cpp`
- **Mô tả**: Check VM bằng `CPUID` leaf 0x1 bit 31 (hypervisor present) sẽ flag Windows VBS/Hyper-V là VM.
- **Rủi ro**: False positive lockout trên Windows 11 có VBS/Credential Guard enabled.

### 6. RDTSC Timing Attack False Positive
- **File**: `src/Ring3_UserApp/host/src/IntegrityChecker.cpp`
- **Mô tả**: Kiểm tra thời gian thực thi qua `RDTSC` quá nhạy, context switch bình thường cũng trigger.
- **Rủi ro**: Khoá thi nhầm khi hệ thống bận.

### 7. Thread Cancellation Deadlock (Shutdown)
- **File**: `src/Ring3_UserApp/host/src/main.cpp`
- **Mô tả**: `ListenForEvent` bị block trong kernel IOCTL, `WinMain` join thread → deadlock vĩnh viễn khi shutdown.
- **Khuyến nghị**: Thêm cancellation event hoặc CancelIo trước join.

### 8. JSON Injection trong `HandleReactMessage`
- **File**: `src/Ring3_UserApp/host/src/MessageBridge.cpp`
- **Mô tả**: Parse JSON thủ công (`json.find` + `std::stoul`) không escape, dễ crash hoặc injection.
- **Khuyến nghị**: Dùng thư viện JSON (nlohmann/json hoặc RapidJSON).

### 9. Domain Verification Bypass
- **File**: `src/Ring3_UserApp/host/src/MessageBridge.cpp`
- **Mô tả**: Kiểm tra domain IPC lỏng lẻo, `http://attacker-localhost.com` có thể vượt qua.

### 10. Memory Leak — `m_history` Vector
- **File**: `src/Ring3_UserApp/host/src/DynamicScanner.cpp`
- **Mô tả**: `m_history` vector không bao giờ được clear, tích lũy bộ nhớ vô hạn.

### 11. Clipboard Clearing Mỗi 3 Giây
- **File**: `src/Ring3_UserApp/host/src/main.cpp`
- **Mô tả**: Xóa clipboard toàn hệ thống mỗi 3 giây ảnh hưởng trải nghiệm người dùng.

---

## 🟡 Lỗi Nhỏ (Low)

### 12. Parent Process Path Validation Yếu
- **Mô tả**: Chỉ kiểm tra filename thay vì đường dẫn tuyệt đối của parent process.

### 13. 4-Minute Cache Clear Spike
- **Mô tả**: Cache clear toàn bộ process mỗi 4 phút gây CPU/Disk I/O spike.

---

**Tổng kết**: 3 Critical, 8 Medium, 2 Low — cần ưu tiên fix #1, #2, #3 trước.
