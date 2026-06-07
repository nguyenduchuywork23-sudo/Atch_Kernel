#include "../inc/LoadImageNotify.h"
#include "../inc/Callbacks.h"
#include "../inc/IoctlHandler.h"

#include "../inc/CompileTimeHash.h"

// Global resolved system directory paths (NT path format)
static UNICODE_STRING g_SystemRootPath = { 0, 0, NULL };
static UNICODE_STRING g_SysWow64Path = { 0, 0, NULL };
static BOOLEAN g_SystemPathsResolved = FALSE;

// Resolve the system root directory from \SystemRoot\ symbolic link
static NTSTATUS ResolveSystemRootPath()
{
    NTSTATUS status;
    HANDLE linkHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING linkName;
    WCHAR targetBuffer[260]; // MAX_PATH equivalent
    UNICODE_STRING targetString;
    ULONG returnedLength = 0;

    // Open the \SystemRoot symbolic link (always available in NT namespace)
    RtlInitUnicodeString(&linkName, L"\\SystemRoot");
    InitializeObjectAttributes(&objAttr, &linkName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, &objAttr);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Atch_Kernel] Failed to open \\SystemRoot symbolic link. Status: 0x%X\n", status));
        return status;
    }

    // Query the target of the symbolic link
    targetString.Buffer = targetBuffer;
    targetString.Length = 0;
    targetString.MaximumLength = sizeof(targetBuffer);

    status = ZwQuerySymbolicLinkObject(linkHandle, &targetString, &returnedLength);
    ZwClose(linkHandle);

    if (!NT_SUCCESS(status)) {
        KdPrint(("[Atch_Kernel] Failed to query \\SystemRoot target. Status: 0x%X\n", status));
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

    g_SystemPathsResolved = TRUE;
    KdPrint(("[Atch_Kernel] Resolved system paths: %wZ and %wZ\n", &g_SystemRootPath, &g_SysWow64Path));
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
                if (RtlPrefixUnicodeString(&g_SystemRootPath, FullImageName, TRUE) ||
                    RtlPrefixUnicodeString(&g_SysWow64Path, FullImageName, TRUE)) {
                    isSafePath = TRUE;
                }
            }

            if (!isSafePath) {
                KdPrint(("[Atch_Kernel] Suspicious DLL Injection Detected: %wZ\n", FullImageName));
                LockExam();
                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"Suspicious DLL Injection");
                NotifyViolationToRing3((ULONG)(ULONG_PTR)ProcessId, &msg, VIOLATION_DLL_INJECTION);
            }
        }
        else if (ProcessId == 0) // Driver loading
        {
            // Zero-Trust: If the exam is running, NO new drivers should be loaded!
            if (examClientPid != 0 && !IsExamLocked())
            {
                KdPrint(("[Atch_Kernel] Zero-Trust BYOVD Block: Driver loaded during exam: %wZ\n", FullImageName));
                LockExam();
                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"Driver loaded during exam");
                NotifyViolationToRing3(0, &msg, VIOLATION_BYOVD_DETECTED);
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
        KdPrint(("[Atch_Kernel] Warning: Failed to resolve system root paths. Status: 0x%X\n", resolveStatus));
        // Continue anyway - DLL injection checks will be conservative (all paths flagged)
    }
    
    NTSTATUS status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (NT_SUCCESS(status))
    {
        InterlockedExchange(&g_LoadImageNotifyRegistered, 1);
        KdPrint(("[Atch_Kernel] LoadImageNotify registered successfully.\n"));
    }
    else
    {
        KdPrint(("[Atch_Kernel] Failed to register LoadImageNotify. Status: 0x%X\n", status));
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
            KdPrint(("[Atch_Kernel] LoadImageNotify unregistered successfully.\n"));
        }
        else
        {
            KdPrint(("[Atch_Kernel] Failed to unregister LoadImageNotify. Status: 0x%X\n", status));
        }
    }

    // Free resolved path buffers
    if (g_SystemRootPath.Buffer != NULL) {
        ExFreePoolWithTag(g_SystemRootPath.Buffer, 'pSLI');
        g_SystemRootPath.Buffer = NULL;
    }
    if (g_SysWow64Path.Buffer != NULL) {
        ExFreePoolWithTag(g_SysWow64Path.Buffer, 'pSLI');
        g_SysWow64Path.Buffer = NULL;
    }
    g_SystemPathsResolved = FALSE;
}
