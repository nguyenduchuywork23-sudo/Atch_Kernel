# Báo Cáo Bảo Mật — React Frontend UI

**Ngày**: 25/07/2026  
**Phạm vi**: `src/Ring3_UserApp/ui/`  
**Lưu ý**: Đây là báo cáo chỉ-đọc, KHÔNG thực hiện sửa code.

---

## 🔴 Lỗi Nghiêm Trọng (Critical)

### 1. Hardcoded Fallback Session Token
- **File**: `src/Ring3_UserApp/ui/src/App.tsx`
- **Mô tả**: Token dự phòng `'EXAM_2026_XYZ'` được ghi cứng trong code.
- **Rủi ro**: Bypass xác thực hoàn toàn nếu backend không trả token.

### 2. XSS qua Unsanitized `<iframe>` src
- **File**: `src/Ring3_UserApp/ui/src/App.tsx`
- **Mô tả**: Thuộc tính `src` của `<iframe>` nhận URL động không được sanitize → DOM-based XSS (VD: `javascript:alert(1)`).
- **Rủi ro**: Thực thi mã tùy ý trong context ứng dụng.

### 3. Wildcard `postMessage` Target Origin
- **File**: `src/Ring3_UserApp/ui/src/` (Bridge module)
- **Mô tả**: `window.postMessage('*')` broadcast tới mọi origin.
- **Rủi ro**: Tab/iframe khác có thể đọc tin nhắn IPC chứa token.

---

## 🟠 Lỗi Trung Bình (Medium)

### 4. Missing `event.origin` Validation
- **File**: `src/Ring3_UserApp/ui/src/` (Bridge module)
- **Mô tả**: Không kiểm tra `event.origin` khi nhận `postMessage` → attacker có thể giả mạo tin nhắn host (VD: `VIOLATION_DETECTED`).

### 5. JWT Token lưu trong `localStorage`
- **File**: `src/Ring3_UserApp/ui/src/api/index.ts`
- **Mô tả**: Access token lưu trong `localStorage` thay vì `httpOnly cookie`.
- **Rủi ro**: XSS có thể đánh cắp token.

### 6. Missing Token Invalidation (401/403)
- **File**: `src/Ring3_UserApp/ui/src/api/index.ts`
- **Mô tả**: Khi nhận 401/403, token không bị xóa khỏi storage → token lỗi vẫn được gửi liên tục.

### 7. Iframe thiếu `sandbox` và `referrerPolicy`
- **File**: `src/Ring3_UserApp/ui/src/App.tsx`
- **Mô tả**: `<iframe>` load nội dung thi nhưng thiếu thuộc tính bảo mật.

### 8. Admin URL Không Validated
- **File**: `src/Ring3_UserApp/ui/src/` (Admin config)
- **Mô tả**: Admin có thể lưu URL mục tiêu tùy ý không được kiểm tra hợp lệ.

### 9. Console Log Nhạy Cảm
- **File**: `src/Ring3_UserApp/ui/src/` (Bridge module)
- **Mô tả**: Log IPC payload chứa token ra console trong production.

---

## 🟡 Lỗi Nhỏ (Low)

### 10. Thiếu CSP Meta Tag
- **File**: `src/Ring3_UserApp/ui/index.html`
- **Mô tả**: Không có Content-Security-Policy → dễ bị inject script.

### 11. Dependencies Outdated
- **File**: `src/Ring3_UserApp/ui/package.json`
- **Mô tả**: React, Vite, TypeScript chưa cập nhật bản vá mới nhất.

### 12. Default Credentials trong UI Form
- **Mô tả**: Form hints hiển thị credentials mặc định.

---

**Tổng kết**: 3 Critical, 6 Medium, 3 Low — ưu tiên fix #1, #2, #3 trước.
