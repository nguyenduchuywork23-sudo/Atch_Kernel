#include "../inc/Callbacks.h"
#include "../inc/IoctlHandler.h"
#include "../inc/CompileTimeHash.h"

extern "C" PCHAR PsGetProcessImageFileName(PEPROCESS Process);

// Biến lưu cookie đăng ký
static LARGE_INTEGER g_RegistryCookie = { 0 };
static PVOID g_ObRegistrationHandle = NULL;
static volatile LONG g_ProcessCallbackRegistered = 0;
static PDEVICE_OBJECT g_DeviceObjectForWorkItems = NULL;
volatile LONG g_OutstandingWorkItems = 0;

void SetDeviceObjectForCallbacks(PDEVICE_OBJECT DeviceObject) {
    InterlockedExchangePointer((PVOID volatile*)&g_DeviceObjectForWorkItems, DeviceObject);
}

// 1. Process Callback
void ProcessNotifyCallbackEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        if (CreateInfo->ImageFileName != NULL) {
            PCUNICODE_STRING imageName = CreateInfo->ImageFileName;
            
            if (imageName->Buffer != NULL && imageName->Length > 0) {
                USHORT lastSlashPos = 0;
                for (USHORT i = 0; i < imageName->Length / sizeof(WCHAR); i++) {
                    if (imageName->Buffer[i] == L'\\') {
                        lastSlashPos = i + 1;
                    }
                }
                
                UNICODE_STRING fileName;
                fileName.Buffer = &imageName->Buffer[lastSlashPos];
                fileName.Length = imageName->Length - (lastSlashPos * sizeof(WCHAR));
                fileName.MaximumLength = fileName.Length;

                ULONG hash = RuntimeHashUnicodeString(&fileName);

                // Check FNV-1a hashes of blacklisted tools
                if (hash == CompileTimeHashW(L"cheatengine-x86_64.exe") ||
                    hash == CompileTimeHashW(L"processhacker.exe") ||
                    hash == CompileTimeHashW(L"ida64.exe") ||
                    hash == CompileTimeHashW(L"x64dbg.exe")) {
                    
                    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                    NotifyViolationToRing3((ULONG)(ULONG_PTR)ProcessId, imageName, VIOLATION_PROCESS_BLACKLISTED);
                    LockExam();
                }
            }
        }
    }
}

// 2. Registry Callback
NTSTATUS RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    // Chặn chỉnh sửa khóa Image File Execution Options (IFEO)
    if (notifyClass == RegNtPreSetValueKey) {
        PREG_PRE_SET_VALUE_KEY_INFORMATION preSetInfo = (PREG_PRE_SET_VALUE_KEY_INFORMATION)Argument2;
        if (preSetInfo != NULL && preSetInfo->Object != NULL) {
            PCUNICODE_STRING valueName = preSetInfo->ValueName;
            
            if (valueName != NULL) {
                UNICODE_STRING targetName;
                RtlInitUnicodeString(&targetName, L"Debugger");

                BOOLEAN match = FALSE;
                if (valueName->Buffer != NULL && valueName->Length > 0 && valueName->Length <= 1024) { // Add reasonable length check
                    ULONG hash = RuntimeHashUnicodeString(valueName);
                    if (hash == CompileTimeHashW(L"debugger")) {
                        match = TRUE;
                    }
                }

                if (match) {
                    UNICODE_STRING regPath;
                    RtlInitUnicodeString(&regPath, L"Registry\\IFEO");
                    NotifyViolationToRing3(0, &regPath, VIOLATION_REGISTRY_TAMPERING);
                    return STATUS_ACCESS_DENIED;
                }
            }
        }
    }
    return STATUS_SUCCESS;
}

// 3. Object Callback (Anti-Kill, Anti-Tampering)
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation == NULL) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    ULONG clientPid = GetExamClientProcessId();
    if (clientPid == 0) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS clientProcess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(UlongToHandle(clientPid), &clientProcess);
    
    if (NT_SUCCESS(status)) {
        if (OperationInformation->Object == clientProcess) {
            // Exclude system processes
            PEPROCESS currentProcess = IoGetCurrentProcess();
            PCHAR processName = PsGetProcessImageFileName(currentProcess);
            BOOLEAN isSystemProcess = FALSE;
            
            if (processName) {
                // simple case-insensitive check for csrss/lsass with spoofing resistance
                if (_stricmp(processName, "csrss.exe") == 0 || _stricmp(processName, "lsass.exe") == 0) {
                    // Spoofing Resistance: Only trust if it's actually a protected process or system session (0)
                    if (PsIsProtectedProcess(currentProcess) || PsGetProcessSessionId(currentProcess) == 0) {
                        isSystemProcess = TRUE;
                    }
                }
            }

            // Block modification if it's not a kernel handle and not a system process
            if (!OperationInformation->KernelHandle && !isSystemProcess) {
                if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION);
                } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                    OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION);
                }
            }
        }
        ObDereferenceObject(clientProcess);
    }

    return OB_PREOP_SUCCESS;
}

typedef struct _TERMINATION_WORK_ITEM_CONTEXT {
    PIO_WORKITEM WorkItem;
    HANDLE ProcessId;
    HANDLE ThreadId;
} TERMINATION_WORK_ITEM_CONTEXT, *PTERMINATION_WORK_ITEM_CONTEXT;

IO_WORKITEM_ROUTINE TerminationWorkerRoutine;
VOID TerminationWorkerRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PTERMINATION_WORK_ITEM_CONTEXT pContext = (PTERMINATION_WORK_ITEM_CONTEXT)Context;
    
    if (pContext->ThreadId != NULL) {
        HANDLE threadHandle = NULL;
        OBJECT_ATTRIBUTES objAttr;
        CLIENT_ID clientId;
        InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        clientId.UniqueProcess = pContext->ProcessId;
        clientId.UniqueThread = pContext->ThreadId;
        if (NT_SUCCESS(ZwOpenThread(&threadHandle, GENERIC_ALL, &objAttr, &clientId)) && threadHandle != NULL) {
            ZwTerminateThread(threadHandle, STATUS_ACCESS_DENIED);
            ZwClose(threadHandle);
        }
    } else {
        HANDLE processHandle = NULL;
        OBJECT_ATTRIBUTES objAttr;
        CLIENT_ID clientId;
        InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        clientId.UniqueProcess = pContext->ProcessId;
        clientId.UniqueThread = NULL;
        if (NT_SUCCESS(ZwOpenProcess(&processHandle, GENERIC_ALL, &objAttr, &clientId)) && processHandle != NULL) {
            ZwTerminateProcess(processHandle, STATUS_ACCESS_DENIED);
            ZwClose(processHandle);
        }
    }
    
    InterlockedDecrement(&g_OutstandingWorkItems);

    if (pContext->WorkItem != NULL) {
        IoFreeWorkItem(pContext->WorkItem);
    }
    ExFreePoolWithTag(pContext, 'mrTW');
}

void ForceKillExamProcess(HANDLE ProcessId)
{
    if (g_DeviceObjectForWorkItems == NULL) return;

    PTERMINATION_WORK_ITEM_CONTEXT pContext = (PTERMINATION_WORK_ITEM_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TERMINATION_WORK_ITEM_CONTEXT), 'mrTW');
    if (pContext != NULL) {
        pContext->ProcessId = ProcessId;
        pContext->ThreadId = NULL;
        pContext->WorkItem = IoAllocateWorkItem(g_DeviceObjectForWorkItems);
        if (pContext->WorkItem != NULL) {
            InterlockedIncrement(&g_OutstandingWorkItems);
            IoQueueWorkItem(pContext->WorkItem, TerminationWorkerRoutine, DelayedWorkQueue, pContext);
        } else {
            ExFreePoolWithTag(pContext, 'mrTW');
        }
    }
}

void ForceKillExamThread(HANDLE ProcessId, HANDLE ThreadId)
{
    if (g_DeviceObjectForWorkItems == NULL) return;

    PTERMINATION_WORK_ITEM_CONTEXT pContext = (PTERMINATION_WORK_ITEM_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TERMINATION_WORK_ITEM_CONTEXT), 'mrTW');
    if (pContext != NULL) {
        pContext->ProcessId = ProcessId;
        pContext->ThreadId = ThreadId;
        pContext->WorkItem = IoAllocateWorkItem(g_DeviceObjectForWorkItems);
        if (pContext->WorkItem != NULL) {
            InterlockedIncrement(&g_OutstandingWorkItems);
            IoQueueWorkItem(pContext->WorkItem, TerminationWorkerRoutine, DelayedWorkQueue, pContext);
        } else {
            ExFreePoolWithTag(pContext, 'mrTW');
        }
    }
}

NTSTATUS RegisterSecurityCallbacks(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    NTSTATUS firstFailure = STATUS_SUCCESS;

    // Đăng ký Process Callback
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (NT_SUCCESS(status)) {
        InterlockedExchange(&g_ProcessCallbackRegistered, 1);
    } else {
        KdPrint(("AtchKernel: Đăng ký Process Callback thất bại. Status: 0x%X\n", status));
        if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
    }

    // Đăng ký Registry Callback
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"360000"); // Độ cao (Altitude) đăng ký
    status = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_RegistryCookie, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AtchKernel: Đăng ký Registry Callback thất bại. Status: 0x%X\n", status));
        if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
    }

    // Đăng ký ObCallback
    OB_OPERATION_REGISTRATION obOpReg;
    obOpReg.ObjectType = PsProcessType;
    obOpReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOpReg.PreOperation = PreOperationCallback;
    obOpReg.PostOperation = NULL;

    OB_CALLBACK_REGISTRATION obReg;
    obReg.Version = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 1;
    RtlInitUnicodeString(&altitude, L"360001");
    obReg.Altitude = altitude;
    obReg.RegistrationContext = NULL;
    obReg.OperationRegistration = &obOpReg;

    status = ObRegisterCallbacks(&obReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AtchKernel: Đăng ký ObCallbacks thất bại. Status: 0x%X\n", status));
        if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
    }

    return firstFailure;
}

void UnregisterSecurityCallbacks()
{
    if (InterlockedOr(&g_ProcessCallbackRegistered, 0) != 0) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
        InterlockedExchange(&g_ProcessCallbackRegistered, 0);
    }

    if (g_RegistryCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegistryCookie);
        g_RegistryCookie.QuadPart = 0;
    }

    if (g_ObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
    }
}

void DrainWorkItems()
{
    // Wait for all outstanding work items to complete (max 5 seconds)
    const LONG maxIterations = 50; // 50 * 100ms = 5 seconds
    LARGE_INTEGER delay;
    delay.QuadPart = -1000000LL; // 100ms in 100-nanosecond intervals

    for (LONG i = 0; i < maxIterations; i++) {
        if (InterlockedOr(&g_OutstandingWorkItems, 0) == 0) {
            break;
        }
        KdPrint(("AtchKernel: DrainWorkItems - Waiting for %ld outstanding work items...\n",
                 InterlockedOr(&g_OutstandingWorkItems, 0)));
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    if (InterlockedOr(&g_OutstandingWorkItems, 0) != 0) {
        KdPrint(("AtchKernel: DrainWorkItems - WARNING: %ld work items still outstanding after timeout!\n",
                 InterlockedOr(&g_OutstandingWorkItems, 0)));
    }
}
