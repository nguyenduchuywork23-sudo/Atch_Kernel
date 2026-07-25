// IntegrityChecker.cpp
// [Ring 3 ONLY] Triển khai cơ chế tự bảo vệ liên tục ở User Mode.
// Chạy như một background thread, kiểm tra định kỳ mọi nguy cơ.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "IntegrityChecker.h"
#include "Logger.h"
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

typedef NTSTATUS(NTAPI* pfnNtQueryVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
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
    LOG_INFO("IntegrityChecker: Starting up and generating whitelist...");
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
    LOG_INFO("IntegrityChecker: Whitelisted " + std::to_string(m_whitelistedModules.size()) + " modules.");

    ComputeInitialChecksum();
    LOG_INFO("IntegrityChecker: Computed text section checksum.");

    CacheIAT();
    ErasePEHeader();
    LOG_INFO("IntegrityChecker: Erased PE Header (Anti-Dump).");

    m_running = true;
    m_thread = std::thread([this, intervalMs]() {
        LOG_INFO("IntegrityChecker: Thread started.");
        while (m_running.load()) {
            ULONGLONG startTick = GetTickCount64();
            RunChecks();
            for (auto i = decltype(intervalMs){0}; i < intervalMs; i += 100) {
                if (!m_running.load()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            ULONGLONG endTick = GetTickCount64();
            if (endTick - startTick > intervalMs + 5000) {
                m_callback(L"INTEGRITY_FAIL: Process suspension detected (Anti-Suspend Watchdog)");
                break;
            }
        }
        LOG_INFO("IntegrityChecker: Thread stopped.");
    });
}

void IntegrityChecker::Stop()
{
    LOG_INFO("IntegrityChecker: Stop requested.");
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

    // [CHECK 3.5] Anti-Injection: API Hooks
    if (HasAPIHooks()) {
        m_callback(L"INTEGRITY_FAIL: API Hook detected (LoadLibrary / OpenProcess)");
        return;
    }

    // [CHECK 3.6] IAT Integrity
    if (CheckIATIntegrity()) {
        m_callback(L"INTEGRITY_FAIL: IAT Hook detected (Imports tampered)");
        return;
    }

    // [CHECK 3.7] Unsigned/Suspicious Module
    if (HasSuspiciousModules()) {
        m_callback(L"INTEGRITY_FAIL: Suspicious unsigned DLL injected (Temp/AppData)");
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

    // [CHECK 6] Advanced Anti-Debug
    if (IsAdvancedDebuggerAttached()) {
        m_callback(L"INTEGRITY_FAIL: Advanced Debugger detected");
        return;
    }

    // [CHECK 7] Blacklisted Tools (Cheat Engine, etc.)
    if (IsBlacklistedToolRunning()) {
        m_callback(L"INTEGRITY_FAIL: Blacklisted hacking tool detected");
        return;
    }

    // [CHECK 7.5] Blacklisted Windows (To catch renamed tools)
    if (IsBlacklistedWindowVisible()) {
        m_callback(L"INTEGRITY_FAIL: Blacklisted window (renamed tool) detected");
        return;
    }

    // [CHECK 8] Anti-VM
    if (IsRunningInVirtualMachine()) {
        m_callback(L"INTEGRITY_FAIL: Virtual Machine / Hypervisor detected");
        return;
    }

    // [CHECK 9] Remote Desktop / Screen Sharing
    if (IsRemoteSessionActive()) {
        m_callback(L"INTEGRITY_FAIL: Remote Desktop session active");
        return;
    }

    // [CHECK 10] Clipboard Protection (Anti-Copy-Paste) - Removed for UX

    // [CHECK 11] Multi-Monitor (Anti-Second-Screen)
    if (GetSystemMetrics(SM_CMONITORS) > 1) {
        m_callback(L"INTEGRITY_FAIL: Multiple monitors detected. Please disconnect external screens.");
        return;
    }

    // [CHECK 12] Memory Integrity (PAGE_EXECUTE_READWRITE without backing module)
    if (HasIllegalMemoryAllocations()) {
        m_callback(L"INTEGRITY_FAIL: Illegal memory allocation (Manual Map / Shellcode) detected");
        return;
    }

    // [CHECK 13] Thread Integrity (Threads starting outside known modules)
    if (HasIllegalThreads()) {
        m_callback(L"INTEGRITY_FAIL: Illegal thread detected (Start address outside module boundaries)");
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

    // Phương pháp 3: Kiểm tra cờ heap NtGlobalFlag (debugger bật cờ 0x70) và BeingDebugged
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    BYTE beingDebugged = *(PBYTE)((PBYTE)pPeb + 2); // Offset 2 on x64
    if (beingDebugged) {
        return true;
    }
    DWORD ntGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0xBC); // Offset 0xBC on x64
    if (ntGlobalFlag & 0x70) {
        return true;
    }
    return false;
}

// ─── [CHECK 1.5] Kiểm tra Debugger Nâng Cao ───────────────────────────────
bool IntegrityChecker::IsAdvancedDebuggerAttached()
{
    // 1. CheckRemoteDebuggerPresent
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent) {
        return true;
    }

    // 2. Timing check (RDTSC)
    // Nếu có debugger đang step qua code, thời gian giữa 2 lệnh RDTSC sẽ rất lớn.
    unsigned __int64 tsc1 = __rdtsc();
    // Do some dummy work
    volatile int dummy = 0;
    for(int i = 0; i < 1000; ++i) { dummy += i; }
    unsigned __int64 tsc2 = __rdtsc();
    
    // Nếu tsc2 - tsc1 quá lớn (ví dụ > 0xFFFFFFFF), rất có thể đang bị trace
    if ((tsc2 - tsc1) > 0xFFFFFFFFFFULL) {
        return true;
    }

    // 3. CloseHandle exception trick
    // Mở một handle không hợp lệ. Nếu đang bị debug, debugger có thể bắt exception này.
    __try {
        CloseHandle(reinterpret_cast<HANDLE>(0x12345678));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Nếu exception xảy ra, có khả năng debugger đang can thiệp vào.
        return true; 
    }

    return false;
}

// ─── [CHECK 2] Kiểm tra Hardware Breakpoint ───────────────────────────────
bool IntegrityChecker::IsHardwareBreakpointSet()
{
    DWORD currentPid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te32{};
    te32.dwSize = sizeof(te32);
    bool found = false;

    if (Thread32First(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == currentPid) {
                HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(hThread, &ctx)) {
                        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                            found = true;
                        }
                    }
                    CloseHandle(hThread);
                }
            }
            if (found) break;
        } while (Thread32Next(hSnap, &te32));
    }
    CloseHandle(hSnap);
    return found;
}

// ─── [CHECK 2.5] Phát hiện API Hooks ──────────────────────────────────────
bool IntegrityChecker::HasAPIHooks()
{
    const char* apis[] = { "LoadLibraryA", "LoadLibraryW", "OpenProcess" };
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return false;

    for (const char* api : apis) {
        FARPROC pFunc = GetProcAddress(hKernel32, api);
        if (pFunc) {
            BYTE firstByte = *reinterpret_cast<BYTE*>(pFunc);
            // 0xE9 = JMP rel32, 0xEB = JMP rel8
            if (firstByte == 0xE9 || firstByte == 0xEB) {
                LOG_WARN(L"IntegrityChecker: API Hook detected!");
                return true;
            }
        }
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
            if (!found) {
                LOG_WARN(L"IntegrityChecker: Found unknown module: " + modName);
                return true; // Module lạ!
            }
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
    for (auto& c : nameStr) c = towlower(c);

    WCHAR winDir[MAX_PATH]{};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    std::wstring winDirStr(winDir);
    for (auto& c : winDirStr) c = towlower(c);

    // Danh sách tiến trình cha được chấp nhận (launcher hợp lệ)
    std::wstring allowed1 = winDirStr + L"\\explorer.exe";
    std::wstring allowed2 = winDirStr + L"\\system32\\cmd.exe";
    std::wstring allowed3 = winDirStr + L"\\system32\\windowspowershell\\v1.0\\powershell.exe";
    std::wstring allowed4 = L"c:\\program files\\powershell\\7\\pwsh.exe";
    
    if (nameStr == allowed1 || nameStr == allowed2 || nameStr == allowed3 || nameStr == allowed4) {
        return true;
    }

    // Tiến trình cha không phải từ danh sách trắng → cảnh báo
    return false;
}

// ─── [CHECK 7] Phát hiện phần mềm gian lận bằng danh sách đen ──────────────
bool IntegrityChecker::IsBlacklistedToolRunning()
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);

    const wchar_t* kBlacklist[] = {
        L"cheatengine",
        L"x64dbg",
        L"x32dbg",
        L"processhacker",
        L"wireshark",
        L"fiddler",
        L"ollydbg",
        L"ida",
        L"ida64",
        L"scylla",
        L"dump",
        L"dnspy",
        L"teamviewer",
        // L"ultraviewer",
        L"anydesk",
        L"rustdesk",
        L"parsec"
    };

    bool detected = false;
    if (Process32FirstW(hSnap, &pe32)) {
        do {
            std::wstring procName(pe32.szExeFile);
            // Đưa về chữ thường để so sánh
            for (auto& c : procName) c = towlower(c);

            for (auto& blacklisted : kBlacklist) {
                if (procName.find(blacklisted) != std::wstring::npos) {
                    LOG_WARN(L"IntegrityChecker: Blacklisted tool found: " + procName);
                    detected = true;
                    break;
                }
            }
            if (detected) break;
        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return detected;
}

// ─── [CHECK 7.5] Phát hiện phần mềm gian lận qua Tiêu đề/Lớp Cửa Sổ ────────
// Cách này chống lại việc sinh viên đổi tên file .exe (ví dụ đổi ultraviewer.exe thành chrome.exe)
// Hàm callback dùng cho EnumWindows
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    bool* detected = reinterpret_cast<bool*>(lParam);
    if (!IsWindowVisible(hwnd)) return TRUE;

    WCHAR windowTitle[256];
    GetWindowTextW(hwnd, windowTitle, sizeof(windowTitle) / sizeof(WCHAR));
    
    std::wstring titleStr(windowTitle);
    for (auto& c : titleStr) c = towlower(c);

    const wchar_t* kBlacklistTitles[] = {
        L"cheat engine",
        // L"ultraviewer",
        L"teamviewer",
        L"anydesk",
        L"x64dbg",
        L"process hacker",
        L"wireshark"
    };

    for (auto& blacklisted : kBlacklistTitles) {
        if (titleStr.find(blacklisted) != std::wstring::npos) {
            LOG_WARN(L"IntegrityChecker: Blacklisted window found: " + titleStr);
            *detected = true;
            return FALSE; // Dừng vòng lặp EnumWindows
        }
    }
    return TRUE; // Tiếp tục vòng lặp
}

bool IntegrityChecker::IsBlacklistedWindowVisible()
{
    bool detected = false;
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&detected));
    return detected;
}

// ─── [CHECK 8] Phát hiện máy ảo (Anti-VM) qua CPUID ───────────────────────
    // Removed CPUID VM check to prevent false positives on Windows 11 VBS
    return false;

// ─── [CHECK 9] Phát hiện Remote Desktop ───────────────────────────────────
bool IntegrityChecker::IsRemoteSessionActive()
{
    // Cờ SM_REMOTESESSION sẽ khác 0 nếu ứng dụng đang chạy qua một phiên Remote Desktop (RDP)
    if (GetSystemMetrics(SM_REMOTESESSION) != 0) {
        return true;
    }
    return false;
}

// ─── [Anti-Dump] Xóa PE Header khỏi bộ nhớ ────────────────────────────────
void IntegrityChecker::ErasePEHeader()
{
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) return;

    auto* pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

    auto* pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hModule) + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD oldProtect = 0;
    SIZE_T headerSize = pNtHeader->OptionalHeader.SizeOfHeaders;

    // Thay đổi quyền bảo vệ bộ nhớ thành PAGE_READWRITE để có thể xóa
    if (VirtualProtect(hModule, headerSize, PAGE_READWRITE, &oldProtect)) {
        // Ghi đè toàn bộ header bằng số 0
        SecureZeroMemory(hModule, headerSize);
        
        // Khôi phục quyền bảo vệ bộ nhớ ban đầu
        DWORD temp = 0;
        VirtualProtect(hModule, headerSize, oldProtect, &temp);
    }
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

// ─── [CHECK 12] Memory Integrity ──────────────────────────────────────────
bool IntegrityChecker::HasIllegalMemoryAllocations()
{
    HANDLE hProc = GetCurrentProcess();
    MEMORY_BASIC_INFORMATION mbi{};
    PVOID addr = 0;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    auto pNtQVM = hNtdll ? reinterpret_cast<pfnNtQueryVirtualMemory>(GetProcAddress(hNtdll, "NtQueryVirtualMemory")) : nullptr;

    while (true) {
        bool success = false;
        if (pNtQVM) {
            SIZE_T retLen = 0;
            NTSTATUS status = pNtQVM(hProc, addr, 0, &mbi, sizeof(mbi), &retLen);
            success = NT_SUCCESS(status);
        } else {
            success = (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi));
        }

        if (!success) break;

        if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE) {
            WCHAR modName[MAX_PATH];
            if (GetModuleFileNameExW(hProc, mbi.AllocationBase, modName, MAX_PATH) == 0) {
                return true;
            }
        }
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    return false;
}

// ─── [CHECK 13] Thread Integrity ──────────────────────────────────────────
typedef NTSTATUS (NTAPI *pfnNtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

bool IntegrityChecker::HasIllegalThreads()
{
    DWORD currentPid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    auto pNtQIT = hNtdll ? reinterpret_cast<pfnNtQueryInformationThread>(GetProcAddress(hNtdll, "NtQueryInformationThread")) : nullptr;
    auto pNtQVM = hNtdll ? reinterpret_cast<pfnNtQueryVirtualMemory>(GetProcAddress(hNtdll, "NtQueryVirtualMemory")) : nullptr;

    THREADENTRY32 te32{};
    te32.dwSize = sizeof(te32);
    bool found = false;

    if (pNtQIT && Thread32First(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == currentPid) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    PVOID startAddr = 0;
                    NTSTATUS status = pNtQIT(hThread, 9 /*ThreadQuerySetWin32StartAddress*/, &startAddr, sizeof(startAddr), nullptr);
                    if (NT_SUCCESS(status) && startAddr != 0) {
                        MEMORY_BASIC_INFORMATION mbi{};
                        bool success = false;
                        if (pNtQVM) {
                            SIZE_T retLen = 0;
                            success = NT_SUCCESS(pNtQVM(GetCurrentProcess(), startAddr, 0, &mbi, sizeof(mbi), &retLen));
                        } else {
                            success = (VirtualQuery(startAddr, &mbi, sizeof(mbi)) != 0);
                        }
                        
                        if (success) {
                            WCHAR modName[MAX_PATH];
                            if (GetModuleFileNameExW(GetCurrentProcess(), mbi.AllocationBase, modName, MAX_PATH) == 0) {
                                found = true;
                            }
                        }
                    }
                    CloseHandle(hThread);
                }
            }
            if (found) break;
        } while (Thread32Next(hSnap, &te32));
    }
    CloseHandle(hSnap);
    return found;
}

void IntegrityChecker::CacheIAT()
{
    HMODULE hSelf = GetModuleHandleW(nullptr);
    if (!hSelf) return;

    auto* pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hSelf);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

    auto* pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hSelf) + pDosHeader->e_lfanew);
    
    IMAGE_DATA_DIRECTORY impDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0) return;

    auto* pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<BYTE*>(hSelf) + impDir.VirtualAddress);

    while (pImportDesc->Name != 0) {
        auto* pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<BYTE*>(hSelf) + pImportDesc->FirstThunk);
        
        while (pThunk->u1.Function != 0) {
            PVOID funcAddr = reinterpret_cast<PVOID>(pThunk->u1.Function);
            m_cachedIAT.push_back(funcAddr);
            pThunk++;
        }
        pImportDesc++;
    }
}

bool IntegrityChecker::CheckIATIntegrity()
{
    if (m_cachedIAT.empty()) return false;
    HMODULE hSelf = GetModuleHandleW(nullptr);
    if (!hSelf) return false;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    auto pNtQVM = hNtdll ? reinterpret_cast<pfnNtQueryVirtualMemory>(GetProcAddress(hNtdll, "NtQueryVirtualMemory")) : nullptr;

    for (PVOID funcAddr : m_cachedIAT) {
        MEMORY_BASIC_INFORMATION mbi{};
        bool success = false;
        if (pNtQVM) {
            SIZE_T retLen = 0;
            success = NT_SUCCESS(pNtQVM(GetCurrentProcess(), funcAddr, 0, &mbi, sizeof(mbi), &retLen));
        } else {
            success = (VirtualQuery(funcAddr, &mbi, sizeof(mbi)) != 0);
        }

        if (success) {
            WCHAR modName[MAX_PATH]{};
            if (GetModuleFileNameExW(GetCurrentProcess(), mbi.AllocationBase, modName, MAX_PATH)) {
                std::wstring wModName = modName;
                for (auto& c : wModName) c = towlower(c);
                
                if (wModName.find(L"\\windows\\") == std::wstring::npos && 
                    wModName.find(L"\\system32\\") == std::wstring::npos &&
                    wModName.find(L"\\syswow64\\") == std::wstring::npos &&
                    wModName.find(L"\\system\\") == std::wstring::npos &&
                    (PVOID)hSelf != mbi.AllocationBase) {
                    LOG_WARN(L"IntegrityChecker: IAT Hook detected: " + wModName);
                    return true; 
                }
            } else {
                return true; // Unbacked memory (Hook)
            }
        }
    }
    return false;
}

bool IntegrityChecker::HasSuspiciousModules()
{
    HMODULE hMods[256]{};
    DWORD cbNeeded = 0;
    HANDLE hProc = GetCurrentProcess();
    if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD count = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < count; ++i) {
            WCHAR name[MAX_PATH]{};
            if (GetModuleFileNameExW(hProc, hMods[i], name, MAX_PATH)) {
                std::wstring modName(name);
                for (auto& c : modName) c = towlower(c);

                if (modName.find(L"\\appdata\\") != std::wstring::npos ||
                    modName.find(L"\\temp\\") != std::wstring::npos ||
                    modName.find(L"\\roaming\\") != std::wstring::npos ||
                    modName.find(L"\\local\\") != std::wstring::npos) {
                    LOG_WARN(L"IntegrityChecker: Suspicious module loaded: " + modName);
                    return true;
                }
            }
        }
    }
    return false;
}

