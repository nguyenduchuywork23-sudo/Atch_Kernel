// DriverController.cpp
// [Ring 3 ONLY] Triển khai giao tiếp với Ring0_CoreDriver qua DeviceIoControl.
#include "DriverController.h"
#include "Logger.h"
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

DriverController::DriverController() = default;

DriverController::~DriverController()
{
    Close();
}

// ─── Mở / Đóng Handle ─────────────────────────────────────────────────────
bool DriverController::Open()
{
    if (m_hDevice != INVALID_HANDLE_VALUE)
        return true; // Đã mở rồi

    m_hDevice = CreateFileW(
        kDeviceName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,                // Security attributes mặc định
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (m_hDevice == INVALID_HANDLE_VALUE) {
        LOG_ERR("DriverController: Failed to open handle to AtchKernel.");
        return false;
    }
    LOG_INFO("DriverController: Successfully opened handle to AtchKernel.");
    return true;
}

void DriverController::Close()
{
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }
}

// ─── Helper IOCTL ─────────────────────────────────────────────────────────
bool DriverController::Ioctl(DWORD ctlCode,
                              PVOID inBuf,  DWORD inSize,
                              PVOID outBuf, DWORD outSize,
                              DWORD* bytesReturned)
{
    if (m_hDevice == INVALID_HANDLE_VALUE)
        return false;

    DWORD dwReturned = 0;
    BOOL ok = DeviceIoControl(
        m_hDevice,
        ctlCode,
        inBuf,  inSize,
        outBuf, outSize,
        &dwReturned,
        nullptr);  // Synchronous call (không dùng OVERLAPPED)

    if (ok == FALSE) {
        LOG_ERR("DriverController: IOCTL " + std::to_string(ctlCode) + " failed with error " + std::to_string(GetLastError()));
    } else {
        LOG_DEBUG("DriverController: IOCTL " + std::to_string(ctlCode) + " succeeded.");
    }

    if (bytesReturned)
        *bytesReturned = dwReturned;

    return ok == TRUE;
}

// ─── IOCTL_AK_INITIALIZE_EXAM ─────────────────────────────────────────────
bool DriverController::InitializeExam(ULONG clientPid,
                                       ULONG securityFlags,
                                       const WCHAR* sessionToken)
{
    EXAM_INIT_DATA data{};
    data.ClientProcessId    = clientPid;
    data.SecurityLevelFlags = securityFlags;
    if (sessionToken)
        wcsncpy_s(data.SessionToken, sessionToken, 63);

    return Ioctl(IOCTL_AK_INITIALIZE_EXAM, &data, sizeof(data));
}

// ─── IOCTL_AK_TERMINATE_EXAM ──────────────────────────────────────────────
bool DriverController::TerminateExam(const WCHAR* sessionToken)
{
    // Dùng WHITELIST_DATA để mang token (tái sử dụng struct)
    WHITELIST_DATA data{};
    if (sessionToken)
        wcsncpy_s(data.SessionToken, sessionToken, 63);
    data.Pid = 0;

    return Ioctl(IOCTL_AK_TERMINATE_EXAM, &data, sizeof(data));
}

// ─── IOCTL_AK_SEND_HEARTBEAT ──────────────────────────────────────────────
bool DriverController::SendHeartbeat(const WCHAR* sessionToken)
{
    WHITELIST_DATA data{};
    if (sessionToken)
        wcsncpy_s(data.SessionToken, sessionToken, 63);

    return Ioctl(IOCTL_AK_SEND_HEARTBEAT, &data, sizeof(data));
}

// ─── IOCTL_AK_ADD_WHITELIST_PID ───────────────────────────────────────────
bool DriverController::AddWhitelistPid(const WCHAR* sessionToken, ULONG pid)
{
    WHITELIST_DATA data{};
    if (sessionToken)
        wcsncpy_s(data.SessionToken, sessionToken, 63);
    data.Pid = pid;

    return Ioctl(IOCTL_AK_ADD_WHITELIST_PID, &data, sizeof(data));
}

// ─── IOCTL_AK_UPDATE_BLACKLIST ────────────────────────────────────────────
bool DriverController::UpdateBlacklist(const WCHAR* sessionToken,
                                        const WCHAR (*items)[256],
                                        ULONG itemCount)
{
    // Tạo buffer động: BLACKLIST_DATA header + mảng tên
    DWORD headerSize = sizeof(BLACKLIST_DATA);
    DWORD itemsSize  = itemCount * 256 * sizeof(WCHAR);
    DWORD totalSize  = headerSize + itemsSize;

    std::vector<BYTE> buf(totalSize, 0);
    auto* header = reinterpret_cast<BLACKLIST_DATA*>(buf.data());

    if (sessionToken)
        wcsncpy_s(header->SessionToken, sessionToken, 63);
    header->ItemCount = itemCount;

    if (items && itemCount > 0) {
        WCHAR* dest = reinterpret_cast<WCHAR*>(buf.data() + headerSize);
        memcpy(dest, items, itemsSize);
    }

    return Ioctl(IOCTL_AK_UPDATE_BLACKLIST, buf.data(), totalSize);
}

// ─── IOCTL_AK_LISTEN_EVENT (Blocking Inverted Call) ───────────────────────
bool DriverController::ListenForEvent(MONITOR_LOG_ENTRY& outEntry)
{
    // Gọi IOCTL này sẽ CHẶN cho đến khi Kernel có sự kiện để gửi.
    // Vì vậy, hàm này phải được gọi từ một thread riêng.
    memset(&outEntry, 0, sizeof(outEntry));
    DWORD bytesReturned = 0;
    return Ioctl(IOCTL_AK_LISTEN_EVENT,
                 nullptr, 0,
                 &outEntry, sizeof(outEntry),
                 &bytesReturned);
}

// ─── IOCTL_AK_UNLOCK_EXAM ─────────────────────────────────────────────────
bool DriverController::UnlockExam(const WCHAR* sessionToken)
{
    WHITELIST_DATA data{};
    if (sessionToken)
        wcsncpy_s(data.SessionToken, sessionToken, 63);

    return Ioctl(IOCTL_AK_UNLOCK_EXAM, &data, sizeof(data));
}
