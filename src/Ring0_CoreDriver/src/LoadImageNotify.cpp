#include "../inc/LoadImageNotify.h"
#include "../inc/Callbacks.h"
#include "../inc/IoctlHandler.h"
#include "../inc/AntiBYOVD.h"

#include "../inc/CompileTimeHash.h"

// Global resolved system directory paths (NT path format)
static UNICODE_STRING g_SystemRootPath = { 0, 0, NULL };
static UNICODE_STRING g_SysWow64Path = { 0, 0, NULL };
// OMEGA-FINAL HIGH-05: Broader Windows root path to cover WinSxS, Microsoft.NET, assembly, etc.
static UNICODE_STRING g_WindowsRootPath = { 0, 0, NULL };
// OMEGA-II CRIT-02: Specific trusted subdirectories instead of broad \Windows\ root
static UNICODE_STRING g_WinSxSPath = { 0, 0, NULL };
static UNICODE_STRING g_MsNetPath = { 0, 0, NULL };
static UNICODE_STRING g_AssemblyPath = { 0, 0, NULL };
// OMEGA-II L02: volatile ensures cross-thread visibility of init flag
static volatile BOOLEAN g_SystemPathsResolved = FALSE;

// Resolve the system root directory from \SystemRoot\ symbolic link
static NTSTATUS ResolveSystemRootPath()
{
    NTSTATUS status;
    HANDLE linkHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING linkName;
    WCHAR targetBuffer[260] = {0}; // MAX_PATH equivalent
    UNICODE_STRING targetString;
    ULONG returnedLength = 0;

    // Open the \SystemRoot symbolic link (always available in NT namespace)
    RtlInitUnicodeString(&linkName, L"\\SystemRoot");
    InitializeObjectAttributes(&objAttr, &linkName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, &objAttr);
    if (!NT_SUCCESS(status)) {
        AtchPrint(("[Atch_Kernel] Failed to open \\SystemRoot symbolic link. Status: 0x%X\n", status));
        return status;
    }

    // Query the target of the symbolic link
    targetString.Buffer = targetBuffer;
    targetString.Length = 0;
    targetString.MaximumLength = sizeof(targetBuffer);

    status = ZwQuerySymbolicLinkObject(linkHandle, &targetString, &returnedLength);
    ZwClose(linkHandle);

    if (!NT_SUCCESS(status)) {
        AtchPrint(("[Atch_Kernel] Failed to query \\SystemRoot target. Status: 0x%X\n", status));
        return status;
    }

    // Ensure the path ends with a backslash for prefix matching
    // targetString now contains something like \Device\Harddisk0\Partition1\Windows
    // We need to append "\\system32\\" and "\\syswow64\\"

    // Allocate g_SystemRootPath = <resolved_path>\system32\ (case-insensitive match later)
    USHORT sys32SuffixLen = (USHORT)(wcslen(L"\\system32\\") * sizeof(WCHAR));
    USHORT sysWow64SuffixLen = (USHORT)(wcslen(L"\\syswow64\\") * sizeof(WCHAR));

    // Allocate System32 path
    g_SystemRootPath.MaximumLength = targetString.Length + sys32SuffixLen + sizeof(WCHAR);
    g_SystemRootPath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, g_SystemRootPath.MaximumLength, 'pSLI');
    if (g_SystemRootPath.Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(g_SystemRootPath.Buffer, targetString.Buffer, targetString.Length);
    g_SystemRootPath.Length = targetString.Length;
    status = RtlAppendUnicodeToString(&g_SystemRootPath, L"\\system32\\");
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_SystemRootPath.Buffer, 'pSLI');
        g_SystemRootPath.Buffer = NULL;
        return status;
    }

    // Allocate SysWOW64 path
    g_SysWow64Path.MaximumLength = targetString.Length + sysWow64SuffixLen + sizeof(WCHAR);
    g_SysWow64Path.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, g_SysWow64Path.MaximumLength, 'pSLI');
    if (g_SysWow64Path.Buffer == NULL) {
        ExFreePoolWithTag(g_SystemRootPath.Buffer, 'pSLI');
        g_SystemRootPath.Buffer = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(g_SysWow64Path.Buffer, targetString.Buffer, targetString.Length);
    g_SysWow64Path.Length = targetString.Length;
    status = RtlAppendUnicodeToString(&g_SysWow64Path, L"\\syswow64\\");
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_SystemRootPath.Buffer, 'pSLI');
        g_SystemRootPath.Buffer = NULL;
        ExFreePoolWithTag(g_SysWow64Path.Buffer, 'pSLI');
        g_SysWow64Path.Buffer = NULL;
        return status;
    }

    // OMEGA-II CRIT-02: Specific trusted subdirectories to prevent C:\Windows\Temp bypass
    // WinSxS path
    USHORT winsxsSuffixLen = (USHORT)(wcslen(L"\\WinSxS\\") * sizeof(WCHAR));
    g_WinSxSPath.MaximumLength = targetString.Length + winsxsSuffixLen + sizeof(WCHAR);
    g_WinSxSPath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, g_WinSxSPath.MaximumLength, 'pSLI');
    if (g_WinSxSPath.Buffer != NULL) {
        RtlCopyMemory(g_WinSxSPath.Buffer, targetString.Buffer, targetString.Length);
        g_WinSxSPath.Length = targetString.Length;
        RtlAppendUnicodeToString(&g_WinSxSPath, L"\\WinSxS\\");
    }

    // Microsoft.NET path
    USHORT netSuffixLen = (USHORT)(wcslen(L"\\Microsoft.NET\\") * sizeof(WCHAR));
    g_MsNetPath.MaximumLength = targetString.Length + netSuffixLen + sizeof(WCHAR);
    g_MsNetPath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, g_MsNetPath.MaximumLength, 'pSLI');
    if (g_MsNetPath.Buffer != NULL) {
        RtlCopyMemory(g_MsNetPath.Buffer, targetString.Buffer, targetString.Length);
        g_MsNetPath.Length = targetString.Length;
        RtlAppendUnicodeToString(&g_MsNetPath, L"\\Microsoft.NET\\");
    }

    // assembly path
    USHORT asmSuffixLen = (USHORT)(wcslen(L"\\assembly\\") * sizeof(WCHAR));
    g_AssemblyPath.MaximumLength = targetString.Length + asmSuffixLen + sizeof(WCHAR);
    g_AssemblyPath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, g_AssemblyPath.MaximumLength, 'pSLI');
    if (g_AssemblyPath.Buffer != NULL) {
        RtlCopyMemory(g_AssemblyPath.Buffer, targetString.Buffer, targetString.Length);
        g_AssemblyPath.Length = targetString.Length;
        RtlAppendUnicodeToString(&g_AssemblyPath, L"\\assembly\\");
    }

    g_SystemPathsResolved = TRUE;
    AtchPrint(("[Atch_Kernel] Resolved system paths: %wZ, %wZ, WinSxS=%wZ, .NET=%wZ, asm=%wZ\n", &g_SystemRootPath, &g_SysWow64Path, &g_WinSxSPath, &g_MsNetPath, &g_AssemblyPath));
    return STATUS_SUCCESS;
}

void LoadImageNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (FullImageName != NULL && FullImageName->Buffer != NULL && FullImageName->Length > 0)
    {
        ULONG examClientPid = GetExamClientProcessId();

        // 1. DLL Injection Protection
        if (examClientPid != 0 && ProcessId == (HANDLE)(ULONG_PTR)examClientPid)
        {
            BOOLEAN isSafePath = FALSE;

            // Compare full image path against resolved system directories
            if (g_SystemPathsResolved) {
                __try {
                    // OMEGA-II CRIT-02: Specific subdirectory whitelist (blocks C:\Windows\Temp)
                    if (RtlPrefixUnicodeString(&g_SystemRootPath, FullImageName, TRUE) ||
                        RtlPrefixUnicodeString(&g_SysWow64Path, FullImageName, TRUE) ||
                        (g_WinSxSPath.Buffer != NULL && RtlPrefixUnicodeString(&g_WinSxSPath, FullImageName, TRUE)) ||
                        (g_MsNetPath.Buffer != NULL && RtlPrefixUnicodeString(&g_MsNetPath, FullImageName, TRUE)) ||
                        (g_AssemblyPath.Buffer != NULL && RtlPrefixUnicodeString(&g_AssemblyPath, FullImageName, TRUE))) {
                        isSafePath = TRUE;
                    }

                    // OMEGA-III-CRIT-02: DENY-LIST — writable subdirs within System32 that
                    // attackers can abuse for DLL planting. Check AFTER whitelist match.
                    if (isSafePath) {
                        if (CheckSubstring(FullImageName, L"\\spool\\") ||
                            CheckSubstring(FullImageName, L"\\FxsTmp\\") ||
                            CheckSubstring(FullImageName, L"\\Tasks\\") ||
                            CheckSubstring(FullImageName, L"\\Temp\\") ||
                            CheckSubstring(FullImageName, L"\\tracing\\") ||
                            CheckSubstring(FullImageName, L"\\Com\\") ||
                            CheckSubstring(FullImageName, L"\\config\\systemprofile\\")) {
                            isSafePath = FALSE;
                            AtchPrint(("[Atch_Kernel] BLOCKED DLL from writable System32 subdir: %wZ\n", FullImageName));
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    isSafePath = FALSE;
                }
            }

            if (!isSafePath) {
                AtchPrint(("[Atch_Kernel] Suspicious DLL Injection Detected: %wZ\n", FullImageName));
                LockExam();
                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"Suspicious DLL Injection");
                NotifyViolationToRing3((ULONG)(ULONG_PTR)ProcessId, &msg, ViolationType::VIOLATION_DLL_INJECTION);
            }
        }
        else if (ProcessId == 0) // Driver loading
        {
            if (IsVulnerableDriverLoaded(FullImageName)) {
                AtchPrint(("[Atch_Kernel] BYOVD Blacklist Block: %wZ\n", FullImageName));
                LockExam();
                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"Blacklisted Driver Loaded");
                NotifyViolationToRing3(0, &msg, ViolationType::VIOLATION_BYOVD_DETECTED);
            }

            // Zero-Trust: If the exam is running, NO new drivers should be loaded!
            if (examClientPid != 0 && !IsExamLocked())
            {
                AtchPrint(("[Atch_Kernel] Zero-Trust BYOVD Block: Driver loaded during exam: %wZ\n", FullImageName));
                LockExam();
                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"Driver loaded during exam");
                NotifyViolationToRing3(0, &msg, ViolationType::VIOLATION_BYOVD_DETECTED);
            }
        }
    }
}

static volatile LONG g_LoadImageNotifyRegistered = 0;

NTSTATUS InitLoadImageNotify(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // Resolve system root paths at init time for robust path validation
    NTSTATUS resolveStatus = ResolveSystemRootPath();
    if (!NT_SUCCESS(resolveStatus)) {
        AtchPrint(("[Atch_Kernel] Warning: Failed to resolve system root paths. Status: 0x%X\n", resolveStatus));
        // Continue anyway - DLL injection checks will be conservative (all paths flagged)
    }
    
    NTSTATUS status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (NT_SUCCESS(status))
    {
        InterlockedExchange(&g_LoadImageNotifyRegistered, 1);
        AtchPrint(("[Atch_Kernel] LoadImageNotify registered successfully.\n"));
    }
    else
    {
        AtchPrint(("[Atch_Kernel] Failed to register LoadImageNotify. Status: 0x%X\n", status));
    }

    return status;
}

void UnloadImageNotify()
{
    if (InterlockedOr(&g_LoadImageNotifyRegistered, 0)) {
        NTSTATUS status = PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
        if (NT_SUCCESS(status))
        {
            InterlockedExchange(&g_LoadImageNotifyRegistered, 0);
            // OMEGA-II HIGH-03: Grace period for in-flight callbacks.
            // PsRemoveLoadImageNotifyRoutine does NOT synchronize with running callbacks.
            LARGE_INTEGER graceDelay;
            graceDelay.QuadPart = -500000LL; // 50ms
            KeDelayExecutionThread(KernelMode, FALSE, &graceDelay);
            AtchPrint(("[Atch_Kernel] LoadImageNotify unregistered successfully.\n"));
        }
        else
        {
            AtchPrint(("[Atch_Kernel] Failed to unregister LoadImageNotify. Status: 0x%X\n", status));
        }
    }

    // OMEGA-III: Clear flag BEFORE freeing buffers — prevents in-flight callback access
    g_SystemPathsResolved = FALSE;

    // Free resolved path buffers
    if (g_SystemRootPath.Buffer != NULL) {
        ExFreePoolWithTag(g_SystemRootPath.Buffer, 'pSLI');
        g_SystemRootPath.Buffer = NULL;
    }
    if (g_SysWow64Path.Buffer != NULL) {
        ExFreePoolWithTag(g_SysWow64Path.Buffer, 'pSLI');
        g_SysWow64Path.Buffer = NULL;
    }
    // OMEGA-II CRIT-02: Free specific subdirectory path buffers
    if (g_WindowsRootPath.Buffer != NULL) {
        ExFreePoolWithTag(g_WindowsRootPath.Buffer, 'pSLI');
        g_WindowsRootPath.Buffer = NULL;
    }
    if (g_WinSxSPath.Buffer != NULL) {
        ExFreePoolWithTag(g_WinSxSPath.Buffer, 'pSLI');
        g_WinSxSPath.Buffer = NULL;
    }
    if (g_MsNetPath.Buffer != NULL) {
        ExFreePoolWithTag(g_MsNetPath.Buffer, 'pSLI');
        g_MsNetPath.Buffer = NULL;
    }
    if (g_AssemblyPath.Buffer != NULL) {
        ExFreePoolWithTag(g_AssemblyPath.Buffer, 'pSLI');
        g_AssemblyPath.Buffer = NULL;
    }
    g_SystemPathsResolved = FALSE;
}
