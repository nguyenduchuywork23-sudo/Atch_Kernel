# Báo Cáo Bảo Mật — Java Backend (ExamBackend)

**Ngày**: 25/07/2026  
**Phạm vi**: `src/backend/` (Spring Boot)  
**Lưu ý**: Đây là báo cáo chỉ-đọc, KHÔNG thực hiện sửa code.

---

## 🔴 Lỗi Nghiêm Trọng (Critical)

### 1. Hardcoded JWT Signing Key
- **File**: `application.properties` / `SecurityConfig`
- **Mô tả**: JWT secret key ghi cứng trong source code.
- **Rủi ro**: Bất kỳ ai có source đều có thể forge JWT token hợp lệ.

### 2. Hardcoded Database Credentials
- **File**: `application.properties`
- **Mô tả**: Database root password `123456` ghi cứng.
- **Rủi ro**: Truy cập trực tiếp database nếu port bị expose.

### 3. IDOR / Broken Access Control (ExamController)
- **File**: `ExamController.java`
- **Mô tả**: Logic `auth != null` sai → người dùng chưa xác thực có thể submit phiên thi của người khác.
- **Rủi ro**: Bypass kiểm soát truy cập hoàn toàn.

### 4. HWID Auto-binding Hijack
- **File**: `HwidController.java` / `HwidService.java`
- **Mô tả**: Login đầu tiên tự động bind HWID mà không cần xác nhận → attacker login trước sẽ chiếm HWID vĩnh viễn.
- **Rủi ro**: Khoá vĩnh viễn tài khoản sinh viên.

### 5. Unhashed Passwords (AdminController)
- **File**: `AdminController.java`
- **Mô tả**: Tạo user mới lưu password raw text, không qua `BCryptPasswordEncoder`.
- **Rủi ro**: Password lộ nguyên văn nếu database bị leak.

---

## 🟠 Lỗi Trung Bình (Medium)

### 6. JWT Token Expiry Quá Dài (10 giờ)
- **Mô tả**: Token hết hạn sau 10 giờ, không có cơ chế revocation/blacklist.
- **Rủi ro**: Token bị đánh cắp có thể dùng suốt 10 giờ.

### 7. Exam State Machine — Không Enforce Trạng Thái
- **File**: `ExamController.java`
- **Mô tả**: Cho phép submit lại phiên thi đã `COMPLETED`.
- **Rủi ro**: Gian lận — thay đổi bài thi sau khi nộp.

### 8. Thiếu Enforce Thời Gian Tối Đa
- **File**: `ExamController.java`
- **Mô tả**: Chỉ kiểm tra thời gian tối thiểu (< 1 phút) nhưng không giới hạn tối đa.

### 9. CORS Wildcard `*`
- **File**: `SecurityConfig.java`
- **Mô tả**: `allowedOrigins("*")` cho phép mọi domain gửi request.
- **Rủi ro**: CSRF / cross-origin attacks.

### 10. Session Policy Nhầm
- **File**: `SecurityConfig.java`
- **Mô tả**: Dùng `SessionCreationPolicy.IF_REQUIRED` cùng JWT stateless filter → conflict.

### 11. HWID Không Kiểm Tra Ngoài Login
- **Mô tả**: HWID chỉ validate lúc login; submit và endpoint khác không kiểm tra → token bị đánh cắp bypass HWID.

### 12. Missing Security Log Endpoint
- **Mô tả**: `POST /api/security-logs` không tồn tại → client gửi violation log bị 404.

### 13. Zero Rate Limiting
- **Mô tả**: Không rate limit trên `/api/auth/login` → brute-force thoải mái.

### 14. `submissionData` Bị Bỏ Qua
- **File**: `ExamController.java`
- **Mô tả**: Dữ liệu bài thi gửi lên hoàn toàn bị ignored, không persist.

---

## 🟡 Lỗi Nhỏ (Low)

### 15. Spring Boot Version EOL
- **File**: `pom.xml`
- **Mô tả**: Dùng `spring-boot-starter-parent 3.3.1` — có CVE Path Traversal, cần 3.3.6+.

### 16. Exception Handling Yếu
- **Mô tả**: Nuốt generic `Exception`, trả error structure không thống nhất, thiếu `GlobalExceptionHandler`.

### 17. Entity Expose Trường Nhạy Cảm
- **Mô tả**: Một số Entity thiếu `@JsonIgnore` trên trường password/secret.

---

**Tổng kết**: 5 Critical, 9 Medium, 3 Low — ưu tiên fix #1–#5 ngay lập tức.
