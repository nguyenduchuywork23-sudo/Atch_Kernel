// IntegrityChecker.cpp
// [Ring 3 ONLY] Triển khai cơ chế tự bảo vệ liên tục ở User Mode.
// Chạy như một background thread, kiểm tra định kỳ mọi nguy cơ.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "IntegrityChecker.h"
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#include <array>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

// Prototype nội bộ - gọi trực tiếp NtQueryInformationProcess để tránh bị hook ở user32/kernel32
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
);

IntegrityChecker::IntegrityChecker(IntegrityViolationCallback callback)
    : m_callback(std::move(callback))
{
}

IntegrityChecker::~IntegrityChecker()
{
    Stop();
}

void IntegrityChecker::Start(DWORD intervalMs)
{
    // Chụp trạng thái module ban đầu (whitelist)
    HMODULE hMods[256]{};
    DWORD   cbNeeded = 0;
    HANDLE  hProc = GetCurrentProcess();
    if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD count = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < count; ++i) {
            WCHAR name[MAX_PATH]{};
            if (GetModuleFileNameExW(hProc, hMods[i], name, MAX_PATH)) {
                m_whitelistedModules.push_back(std::wstring(name));
            }
        }
    }

    ComputeInitialChecksum();

    m_running = true;
    m_thread = std::thread([this, intervalMs]() {
        while (m_running.load()) {
            RunChecks();
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
    });
}

void IntegrityChecker::Stop()
{
    m_running = false;
    if (m_thread.joinable())
        m_thread.join();
}

// ─── Thực hiện toàn bộ kiểm tra trong một vòng ────────────────────────────
void IntegrityChecker::RunChecks()
{
    // [CHECK 1] Anti-Debug: Debugger được đính vào?
    if (IsDebuggerAttached()) {
        m_callback(L"INTEGRITY_FAIL: Debugger detected (user mode)");
        return;
    }

    // [CHECK 2] Anti-Debug: Breakpoint phần cứng được đặt?
    if (IsHardwareBreakpointSet()) {
        m_callback(L"INTEGRITY_FAIL: Hardware breakpoint detected");
        return;
    }

    // [CHECK 3] DLL Injection: Có module lạ nào được nạp không?
    if (HasUnknownModulesInjected()) {
        m_callback(L"INTEGRITY_FAIL: Unknown DLL injected into process");
        return;
    }

    // [CHECK 4] Parent Process: Tiến trình cha có hợp lệ không?
    if (!IsParentProcessLegitimate()) {
        m_callback(L"INTEGRITY_FAIL: Illegitimate parent process detected");
        return;
    }

    // [CHECK 5] CRC Checksum: .text section có bị patch trong bộ nhớ không?
    if (!ValidateChecksum()) {
        m_callback(L"INTEGRITY_FAIL: Memory tampering (code section CRC mismatch)");
        return;
    }
}

// ─── [CHECK 1] Kiểm tra Debugger ──────────────────────────────────────────
bool IntegrityChecker::IsDebuggerAttached()
{
    // Phương pháp 1: Win32 API thông thường
    if (::IsDebuggerPresent())
        return true;

    // Phương pháp 2: Gọi thẳng NtQueryInformationProcess để tránh user-mode hook
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto pNtQIP = reinterpret_cast<pfnNtQueryInformationProcess>(
            GetProcAddress(hNtdll, "NtQueryInformationProcess"));
        if (pNtQIP) {
            DWORD isRemoteDebugger = 0;
            NTSTATUS status = pNtQIP(
                GetCurrentProcess(),
                ProcessDebugPort,       // 0x07 - truy vấn cổng debug
                &isRemoteDebugger,
                sizeof(DWORD),
                nullptr);
            if (NT_SUCCESS(status) && isRemoteDebugger != 0)
                return true;

            // ProcessDebugFlags (0x1F): Nếu kết quả == 0, có debugger
            DWORD debugFlags = 0;
            status = pNtQIP(
                GetCurrentProcess(),
                static_cast<PROCESSINFOCLASS>(0x1F),
                &debugFlags,
                sizeof(DWORD),
                nullptr);
            if (NT_SUCCESS(status) && debugFlags == 0)
                return true;
        }
    }

    // Phương pháp 3: Kiểm tra cờ heap NtGlobalFlag (debugger bật cờ 0x70)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    DWORD ntGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0xBC); // Offset 0xBC on x64
    if (ntGlobalFlag & 0x70) {
        return true;
    }
    return false;
}

// ─── [CHECK 2] Kiểm tra Hardware Breakpoint ───────────────────────────────
bool IntegrityChecker::IsHardwareBreakpointSet()
{
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        // DR0-DR3: địa chỉ breakpoint phần cứng. Nếu != 0 thì đang bị theo dõi.
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
            return true;
    }
    return false;
}

// ─── [CHECK 3] Phát hiện DLL Injection ────────────────────────────────────
bool IntegrityChecker::HasUnknownModulesInjected()
{
    if (m_whitelistedModules.empty())
        return false; // Chưa khởi tạo, bỏ qua

    HMODULE hMods[256]{};
    DWORD   cbNeeded = 0;
    HANDLE  hProc = GetCurrentProcess();
    if (!EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded))
        return false;

    DWORD count = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < count; ++i) {
        WCHAR name[MAX_PATH]{};
        if (GetModuleFileNameExW(hProc, hMods[i], name, MAX_PATH)) {
            std::wstring modName(name);
            bool found = false;
            for (auto& wl : m_whitelistedModules) {
                if (_wcsicmp(wl.c_str(), modName.c_str()) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found)
                return true; // Module lạ!
        }
    }
    return false;
}

// ─── [CHECK 4] Kiểm tra tiến trình cha ────────────────────────────────────
bool IntegrityChecker::IsParentProcessLegitimate()
{
    // Lấy PID tiến trình cha thông qua PROCESSENTRY32
    DWORD currentPid = GetCurrentProcessId();
    DWORD parentPid  = 0;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return true; // Không kiểm tra được thì bỏ qua

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);
    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (pe32.th32ProcessID == currentPid) {
                parentPid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);

    if (parentPid == 0)
        return true;

    // Lấy tên tiến trình cha
    HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    if (!hParent)
        return true; // Cha đã chết → bình thường (ví dụ: launched từ Explorer)

    WCHAR parentName[MAX_PATH]{};
    DWORD size = MAX_PATH;
    QueryFullProcessImageNameW(hParent, 0, parentName, &size);
    CloseHandle(hParent);

    std::wstring nameStr(parentName);

    // Danh sách tiến trình cha được chấp nhận (launcher hợp lệ)
    const wchar_t* kAllowedParents[] = {
        L"explorer.exe",
        L"cmd.exe",
        L"powershell.exe",
        L"pwsh.exe",
        // Thêm launcher chính thức ở đây
    };
    for (auto& ap : kAllowedParents) {
        if (nameStr.size() >= wcslen(ap)) {
            std::wstring tail = nameStr.substr(nameStr.size() - wcslen(ap));
            if (_wcsicmp(tail.c_str(), ap) == 0)
                return true;
        }
    }

    // Tiến trình cha không phải từ danh sách trắng → cảnh báo
    return false;
}

// ─── [CHECK 5] CRC Checksum của .text section ──────────────────────────────
void IntegrityChecker::ComputeInitialChecksum()
{
    HMODULE hSelf = GetModuleHandleW(nullptr); // Base của chính file .exe
    if (!hSelf) return;

    auto* dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(hSelf);
    auto* ntHdrs = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<BYTE*>(hSelf) + dosHdr->e_lfanew);
    auto* section = IMAGE_FIRST_SECTION(ntHdrs);

    for (WORD i = 0; i < ntHdrs->FileHeader.NumberOfSections; ++i, ++section) {
        if (memcmp(section->Name, ".text", 5) == 0) {
            m_textSectionBase = reinterpret_cast<BYTE*>(hSelf) + section->VirtualAddress;
            m_textSectionSize = section->Misc.VirtualSize;
            m_initialCRC     = ComputeRegionCRC32(m_textSectionBase, m_textSectionSize);
            break;
        }
    }
}

bool IntegrityChecker::ValidateChecksum()
{
    if (!m_textSectionBase || m_textSectionSize == 0)
        return true; // Không tìm thấy section, bỏ qua kiểm tra

    DWORD currentCRC = ComputeRegionCRC32(m_textSectionBase, m_textSectionSize);
    return (currentCRC == m_initialCRC);
}

DWORD IntegrityChecker::ComputeRegionCRC32(const BYTE* data, SIZE_T len)
{
    // CRC-32/ISO-HDLC
    static const std::array<DWORD, 256> kTable = [] {
        std::array<DWORD, 256> t{};
        for (DWORD i = 0; i < 256; ++i) {
            DWORD c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }();

    DWORD crc = 0xFFFFFFFFu;
    for (SIZE_T i = 0; i < len; ++i)
        crc = kTable[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}
