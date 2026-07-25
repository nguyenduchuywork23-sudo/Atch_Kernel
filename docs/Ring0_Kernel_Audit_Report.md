# Báo cáo Kiểm toán Bảo mật: Ring 0 Kernel Driver (Trình điều khiển Hạt nhân)

**Ngày**: 25 tháng 7, 2026
**Mức độ ưu tiên**: Nghiêm trọng (Critical)

## Các Lỗi Phát Hiện

**Lỗi 1: Vi phạm IRQL nghiêm trọng trong hàm `EmergencyCleanupExam`**
- **Vị trí**: `src/Ring0_CoreDriver/src/IoctlHandler.cpp` (Dòng 947 cũ)
- **Lỗ hổng**: Hàm `PsLookupProcessByProcessId` (yêu cầu chạy ở `PASSIVE_LEVEL`) lại được gọi *sau* khi đã chiếm được `FastMutex` (việc này sẽ đẩy IRQL lên mức `APC_LEVEL`).
- **Tác động**: Gây ra lỗi BugCheck ngay lập tức (Màn hình xanh chết chóc / BSOD) `IRQL_NOT_LESS_OR_EQUAL` trên các hệ thống Windows hiện đại, hoặc gây ra treo máy (deadlock) do tranh chấp khóa tài nguyên `PspCidTable`.
- **Trạng thái**: ✅ **ĐÃ SỬA** — Di chuyển `PsLookupProcessByProcessId` ra **trước** khi gọi `ExAcquireFastMutex`, đảm bảo chạy ở `PASSIVE_LEVEL`. Thêm nhánh `else` để dọn dẹp reference khi CAS thất bại. Thêm guard `KeGetCurrentIrql() != PASSIVE_LEVEL`.

**Lỗi 2: Kiểm tra IRQL không đảm bảo an toàn trong `PreOperationCallback`**
- **Vị trí**: `src/Ring0_CoreDriver/src/Callbacks.cpp` (Dòng 413 cũ)
- **Lỗ hổng**: Điều kiện kiểm tra `if (KeGetCurrentIrql() >= DISPATCH_LEVEL)` vẫn cho phép code chạy ở mức `APC_LEVEL`, qua đó cho phép gọi `PsLookupProcessByProcessId` một cách sai luật.
- **Tác động**: Có thể dẫn đến treo máy/BSOD không lường trước được khi thao tác với các handle của tiến trình (process) hoặc luồng (thread) trong ngữ cảnh `APC_LEVEL`.
- **Trạng thái**: ✅ **ĐÃ SỬA** — Đổi điều kiện kiểm tra thành `if (KeGetCurrentIrql() != PASSIVE_LEVEL)` để chỉ cho phép chạy ở đúng mức IRQL an toàn duy nhất.

---

**Lưu ý:** Chức năng Anti-VM (chống máy ảo) trong Ring 0 hiện đang bị vô hiệu hóa (kích hoạt `TESTING BYPASS`) để cho phép test an toàn trên môi trường Proxmox/KVM.
