// IntegrityChecker.h
// [Ring 3 ONLY] Kiểm tra tính toàn vẹn của tiến trình giao diện liên tục.
// Mục đích: Tự bảo vệ ứng dụng Ring 3 khỏi bị:
//   - Đính kèm Debugger (Anti-Debug)
//   - Tiêm DLL lạ vào (DLL Injection detection)
//   - Thao túng bộ nhớ (Memory tampering via CRC hash)
//   - Giả mạo tiến trình cha (Parent Process check)
//   - Breakpoint phần cứng qua thanh ghi DR (HW Breakpoint detection)
#pragma once
#ifndef INTEGRITY_CHECKER_H
#define INTEGRITY_CHECKER_H

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>

// Callback khi phát hiện vi phạm toàn vẹn của Ring 3
using IntegrityViolationCallback = std::function<void(const std::wstring& reason)>;

class IntegrityChecker {
public:
    explicit IntegrityChecker(IntegrityViolationCallback callback);
    ~IntegrityChecker();

    // Bắt đầu vòng lặp kiểm tra nền (background thread)
    void Start(DWORD intervalMs = 3000);
    void Stop();

    // --- Các hàm kiểm tra đơn lẻ (cũng có thể gọi thủ công) ---
    bool IsDebuggerAttached();
    bool IsAdvancedDebuggerAttached(); // Timing, Exception, CheckRemote
    bool IsHardwareBreakpointSet();
    bool HasUnknownModulesInjected();
    bool IsParentProcessLegitimate();
    bool IsBlacklistedToolRunning();
    bool IsBlacklistedWindowVisible();
    bool IsRemoteSessionActive();
    bool IsRunningInVirtualMachine();
    bool HasAPIHooks();
    bool HasIllegalMemoryAllocations();
    bool HasIllegalThreads();
    bool CheckIATIntegrity();
    bool HasSuspiciousModules();
    void ErasePEHeader();

    // Tính toán & lưu CRC của .text section của chính tiến trình này
    void ComputeInitialChecksum();
    // Kiểm tra CRC hiện tại có khớp với ban đầu không
    bool ValidateChecksum();

    void CacheIAT();

private:
    void RunChecks();
    DWORD ComputeRegionCRC32(const BYTE* data, SIZE_T len);

    IntegrityViolationCallback m_callback;
    std::atomic<bool> m_running{ false };
    std::thread m_thread;

    std::vector<PVOID> m_cachedIAT;

    // Danh sách module hợp lệ được chụp lại khi khởi động
    std::vector<std::wstring> m_whitelistedModules;

    // Checksum lúc khởi động
    DWORD m_initialCRC{ 0 };
    BYTE* m_textSectionBase{ nullptr };
    SIZE_T m_textSectionSize{ 0 };
};

#endif // INTEGRITY_CHECKER_H
