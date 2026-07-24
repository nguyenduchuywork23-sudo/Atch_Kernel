// DriverController.h
// [Ring 3 ONLY] Wrapper giao tiếp với Ring0_CoreDriver.sys qua DeviceIoControl.
// Đây là TOÀN BỘ điểm giao tiếp giữa Ring 3 và Ring 0. Ring 0 không được sửa đổi.
#pragma once
#ifndef DRIVER_CONTROLLER_H
#define DRIVER_CONTROLLER_H

#include <windows.h>
#include <string>
#include <functional>
#include "../../../include/SharedDef.h"  // Header dùng chung với Ring 0

// Callback khi Kernel phát hiện vi phạm và gửi lên (Inverted Call)
using KernelEventCallback = std::function<void(const MONITOR_LOG_ENTRY& entry)>;

class DriverController {
public:
    DriverController();
    ~DriverController();

    // Mở handle tới device của driver
    bool Open();
    void Close();
    bool IsOpen() const { return m_hDevice != INVALID_HANDLE_VALUE; }

    // ─── Wrapper cho từng IOCTL ────────────────────────────────────────────

    // IOCTL_AK_INITIALIZE_EXAM: Gửi dữ liệu phiên thi xuống Kernel
    bool InitializeExam(ULONG clientPid, ULONG securityFlags, const WCHAR* sessionToken);

    // IOCTL_AK_TERMINATE_EXAM: Kết thúc phiên thi
    bool TerminateExam(const WCHAR* sessionToken);

    // IOCTL_AK_SEND_HEARTBEAT: Ping để báo UI vẫn sống
    bool SendHeartbeat(const WCHAR* sessionToken);

    // IOCTL_AK_ADD_WHITELIST_PID: Thêm PID vào whitelist
    bool AddWhitelistPid(const WCHAR* sessionToken, ULONG pid);

    // IOCTL_AK_UPDATE_BLACKLIST: Cập nhật danh sách tên tiến trình bị cấm
    bool UpdateBlacklist(const WCHAR* sessionToken,
                         const WCHAR (*items)[256], ULONG itemCount);

    // IOCTL_AK_LISTEN_EVENT: Blocking call - đợi Kernel gửi cảnh báo lên
    // Hàm này CHẶN luồng hiện tại cho đến khi có sự kiện hoặc bị hủy.
    bool ListenForEvent(MONITOR_LOG_ENTRY& outEntry);

    // IOCTL_AK_UNLOCK_EXAM: Mở khóa ngoại vi (chuột/bàn phím)
    bool UnlockExam(const WCHAR* sessionToken);

private:
    // Tên symbolic link của device do Ring0_CoreDriver đăng ký
    static constexpr const wchar_t* kDeviceName = L"\\\\.\\AtchKernel";

    HANDLE m_hDevice{ INVALID_HANDLE_VALUE };

    // Hàm helper nội bộ để gọi IOCTL
    bool Ioctl(DWORD ctlCode, PVOID inBuf, DWORD inSize,
               PVOID outBuf = nullptr, DWORD outSize = 0,
               DWORD* bytesReturned = nullptr);
};

#endif // DRIVER_CONTROLLER_H
