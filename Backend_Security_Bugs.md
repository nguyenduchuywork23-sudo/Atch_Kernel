# Báo Cáo Lỗi Bảo Mật Tầng Backend (Server)

Tài liệu này tổng hợp toàn bộ các lỗ hổng bảo mật web nghiêm trọng (OWASP), sai sót phân quyền, và lỗi thiết kế API trong hệ thống `ExamBackend` (Java Spring Boot).

## 1. Lỗ Hổng Phân Quyền Trầm Trọng (Broken Access Control)

> [!CAUTION]
> Các lỗ hổng này cho phép người dùng (học sinh) vượt quyền và can thiệp vào dữ liệu của người khác, phá vỡ hoàn toàn tính công bằng của kỳ thi.

*   **Học sinh có quyền của Giáo viên (Missing Role Check)**:
    *   Trong `SecurityConfig.java`, quên không gán quyền `.hasRole("TEACHER")` cho endpoint `/api/teacher/**`. Route này bị rơi vào nhánh mặc định `.anyRequest().authenticated()`.
    *   **Hậu quả**: Mọi học sinh đã đăng nhập đều có thể gọi các API mở khóa phòng thi (`/api/teacher/unlock`) hoặc xem log bảo mật của học sinh khác.
*   **Lỗ Hổng IDOR (Insecure Direct Object Reference) Khi Nộp Bài**:
    *   API `POST /api/exams/submit/{sessionId}` nhận ID của session nhưng không đối chiếu xem `sessionId` đó có thuộc về user đang đăng nhập (trong JWT) hay không.
    *   **Hậu quả**: Một học sinh có thể đoán `sessionId` của các bạn trong lớp và gọi API nộp bài thay cho họ, ép hệ thống đóng bài thi của họ sớm.
*   **Lộ Cấu Hình Hệ Thống**:
    *   API `GET /api/config` được đặt thành `.permitAll()`, cho phép người không đăng nhập (anonymous) cũng có thể lấy cấu hình hệ thống.

## 2. Thiếu Cơ Chế Quản Lý Hardware ID (HWID)

*   **Backend "bỏ quên" HWID**:
    *   Phía Client (Ring 0 / Ring 3) có trích xuất Machine GUID để nhận diện thiết bị. Tuy nhiên, Backend hoàn toàn không có endpoint nào tiếp nhận, lưu trữ hay đối chiếu HWID.
    *   **Hậu quả**: Việc nhận diện thiết bị trở nên vô dụng. Học sinh có thể share tài khoản cho người khác thi hộ từ xa trên máy khác, hoặc đăng nhập cùng lúc trên nhiều máy tính.

## 3. Quản Lý Mật Khẩu Yếu Kém

*   **Lưu Mật Khẩu Dạng Plain Text**:
    *   Hệ thống dùng `NoOpPasswordEncoder.getInstance()` thay vì `BCryptPasswordEncoder`.
    *   **Hậu quả**: Mật khẩu được lưu rõ chữ trong database. Nếu file dump MySQL bị rò rỉ, toàn bộ mật khẩu Admin, Giáo viên, và Học sinh sẽ bị xâm phạm trực tiếp.

## 4. Quản Lý Lỗi & Xử Lý Ngoại Lệ Kém (Poor Error Handling)

> [!WARNING]
> Việc không có cơ chế quản lý lỗi có thể để lọt thông tin nhạy cảm của hệ thống ra ngoài (Stacktrace) hoặc làm sập logic luồng (Thread).

*   **Sập Filter JWT (500 Internal Server Error)**:
    *   Trong `JwtFilter.java`, thiếu khối lệnh `try-catch` bọc quanh code parse JWT. Nếu nhận được JWT hết hạn hoặc mã hóa sai, thư viện `jjwt` sẽ throw exception văng thẳng ra ngoài.
    *   **Hậu quả**: Server trả về HTTP 500 thay vì trả về HTTP 401 (Unauthorized).
*   **Không có Global Exception Handler (`@ControllerAdvice`)**:
    *   Không có class bắt lỗi tổng thể. Bất kỳ lỗi `NoSuchElementException` hoặc lỗi truy vấn Database nào cũng sẽ làm Server ném ra trang lỗi 500 mặc định của Spring Boot.
*   **Zero Logging (Hoàn toàn không ghi log)**:
    *   Hệ thống không cài đặt SLF4J / Logback cho Application Layer. Không ghi log đăng nhập thất bại, tạo user, hay lỗi hệ thống.
    *   **Hậu quả**: Quản trị viên bị mù thông tin, không thể truy vết khi xảy ra sự cố hay có dấu hiệu tấn công.

## 5. Thư Viện Hết Hạn & Dính Lỗi Bảo Mật (Vulnerable Dependencies)

*   **Spring Boot 3.2.5 End-Of-Life**:
    *   Bản 3.2.5 đã hết hạn hỗ trợ (EOL). Phiên bản này kéo theo Spring Framework 6.1.6 có chứa nhiều lỗ hổng DoS, Path Traversal (CVE-2024-38816, CVE-2024-38809).
*   **Thư viện JJWT quá cũ**:
    *   Đang dùng bản `0.11.5`. Nên nâng cấp lên `0.12.x`.
