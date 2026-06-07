#include "../inc/LoadImageNotify.h"
#include "../inc/Callbacks.h"
#include "../inc/IoctlHandler.h"

#include "../inc/CompileTimeHash.h"

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
            
            UNICODE_STRING sys32;
            RtlInitUnicodeString(&sys32, L"\\windows\\system32\\");
            UNICODE_STRING syswow;
            RtlInitUnicodeString(&syswow, L"\\windows\\syswow64\\");

            USHORT wcharsCount = FullImageName->Length / sizeof(WCHAR);
            if (wcharsCount >= 18) {
                for (USHORT i = 0; i <= wcharsCount - 18; i++) {
                    UNICODE_STRING subStr;
                    subStr.Buffer = &FullImageName->Buffer[i];
                    subStr.Length = 18 * sizeof(WCHAR);
                    subStr.MaximumLength = subStr.Length;
                    
                    if (RtlCompareUnicodeString(&subStr, &sys32, TRUE) == 0 ||
                        RtlCompareUnicodeString(&subStr, &syswow, TRUE) == 0) {
                        isSafePath = TRUE;
                        break;
                    }
                }
            }

            if (!isSafePath) {
                KdPrint(("[Atch_Kernel] Suspicious DLL Injection Detected: %wZ\n", FullImageName));
                LockExam();
                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"Suspicious DLL Injection");
                NotifyViolationToRing3((ULONG)(ULONG_PTR)ProcessId, &msg, 5); // 5: DLL_INJECTION
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
                NotifyViolationToRing3(0, &msg, 4); // 4: BYOVD_DETECTED
            }
        }
    }
}

BOOLEAN g_LoadImageNotifyRegistered = FALSE;

NTSTATUS InitLoadImageNotify(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    
    NTSTATUS status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (NT_SUCCESS(status))
    {
        g_LoadImageNotifyRegistered = TRUE;
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
    if (g_LoadImageNotifyRegistered) {
        NTSTATUS status = PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
        if (NT_SUCCESS(status))
        {
            g_LoadImageNotifyRegistered = FALSE;
            KdPrint(("[Atch_Kernel] LoadImageNotify unregistered successfully.\n"));
        }
        else
        {
            KdPrint(("[Atch_Kernel] Failed to unregister LoadImageNotify. Status: 0x%X\n", status));
        }
    }
}
