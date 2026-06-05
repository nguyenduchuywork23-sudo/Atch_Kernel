#include "../inc/LoadImageNotify.h"
#include "../inc/Callbacks.h"
#include "../inc/IoctlHandler.h"

void LoadImageNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (FullImageName != NULL)
    {
        KdPrint(("[Atch_Kernel] Image Loaded: %wZ\n", FullImageName));

        ULONG examClientPid = GetExamClientProcessId();

        // Check if DLL is injected into the client process
        if (examClientPid != 0 && ProcessId == (HANDLE)(ULONG_PTR)examClientPid)
        {
            if (FullImageName->Buffer != NULL)
            {
                UNICODE_STRING extUs;
                RtlInitUnicodeString(&extUs, L".dll");
                
                BOOLEAN isDll = FALSE;
                if (FullImageName->Length >= extUs.Length) {
                    UNICODE_STRING suffix;
                    suffix.Length = extUs.Length;
                    suffix.MaximumLength = extUs.Length;
                    suffix.Buffer = (PWCH)((PUCHAR)FullImageName->Buffer + FullImageName->Length - extUs.Length);
                    if (RtlCompareUnicodeString(&suffix, &extUs, TRUE) == 0) {
                        isDll = TRUE;
                    }
                }

                if (isDll) {
                    BOOLEAN inWindows = FALSE;
                    USHORT wcharsCount = FullImageName->Length / sizeof(WCHAR);
                    if (wcharsCount >= 9) {
                        for (USHORT i = 0; i <= wcharsCount - 9; i++) {
                            if (_wcsnicmp(&FullImageName->Buffer[i], L"\\windows\\", 9) == 0) {
                                inWindows = TRUE;
                                break;
                            }
                        }
                    }

                    if (!inWindows) {
                        KdPrint(("[Atch_Kernel] Suspicious DLL Injection Detected: %wZ\n", FullImageName));
                        UNICODE_STRING msg;
                        RtlInitUnicodeString(&msg, L"Suspicious DLL Injection Blocked");
                        NotifyViolationToRing3((ULONG)(ULONG_PTR)ProcessId, &msg, 5); // 5 could be DLL_INJECTION

                        ForceKillExamProcess((HANDLE)(ULONG_PTR)examClientPid);
                    }
                }
            }
        }
        else if (ProcessId == 0) // Driver loading
        {
            if (FullImageName->Buffer != NULL)
            {
                USHORT lastSlashPos = 0;
                for (USHORT i = 0; i < FullImageName->Length / sizeof(WCHAR); i++) {
                    if (FullImageName->Buffer[i] == L'\\') {
                        lastSlashPos = i + 1;
                    }
                }
                
                UNICODE_STRING fileName;
                fileName.Buffer = &FullImageName->Buffer[lastSlashPos];
                fileName.Length = FullImageName->Length - (lastSlashPos * sizeof(WCHAR));
                fileName.MaximumLength = fileName.Length;

                UNICODE_STRING gdrvName, iqvwName;
                RtlInitUnicodeString(&gdrvName, L"gdrv.sys");
                RtlInitUnicodeString(&iqvwName, L"iqvw64e.sys");

                if (RtlCompareUnicodeString(&fileName, &gdrvName, TRUE) == 0 ||
                    RtlCompareUnicodeString(&fileName, &iqvwName, TRUE) == 0)
                {
                    KdPrint(("[Atch_Kernel] BYOVD Detected: %wZ\n", FullImageName));
                    UNICODE_STRING msg;
                    RtlInitUnicodeString(&msg, L"Vulnerable Driver (BYOVD) Blocked");
                    NotifyViolationToRing3(0, &msg, 4); // 4 could be BYOVD_DETECTED
                    
                    if (examClientPid != 0) {
                        ForceKillExamProcess((HANDLE)(ULONG_PTR)examClientPid);
                    }
                }
            }
        }
    }
}

NTSTATUS InitLoadImageNotify(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    
    NTSTATUS status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (NT_SUCCESS(status))
    {
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
    NTSTATUS status = PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (NT_SUCCESS(status))
    {
        KdPrint(("[Atch_Kernel] LoadImageNotify unregistered successfully.\n"));
    }
    else
    {
        KdPrint(("[Atch_Kernel] Failed to unregister LoadImageNotify. Status: 0x%X\n", status));
    }
}
