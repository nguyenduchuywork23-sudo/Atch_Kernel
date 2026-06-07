#include "../inc/Callbacks.h"
#include "../inc/IoctlHandler.h"
#include "../inc/CompileTimeHash.h"

extern "C" PCHAR PsGetProcessImageFileName(PEPROCESS Process);

// Biến lưu cookie đăng ký
static LARGE_INTEGER g_RegistryCookie = { 0 };
static PVOID g_ObRegistrationHandle = NULL;
static BOOLEAN g_ProcessCallbackRegistered = FALSE;
static BOOLEAN g_ThreadCallbackRegistered = FALSE;

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
                    NotifyViolationToRing3((ULONG)(ULONG_PTR)ProcessId, imageName, 2); // 2: PROCESS_BLACKLISTED
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
                __try {
                    // preSetInfo->ValueName and its Buffer may point to user-mode memory
                    ProbeForRead((PVOID)valueName, sizeof(UNICODE_STRING), 1);
                    if (valueName->Buffer != NULL && valueName->Length > 0) {
                        ProbeForRead((PVOID)valueName->Buffer, valueName->Length, 1);
                        
                        ULONG hash = RuntimeHashUnicodeString(valueName);
                        if (hash == CompileTimeHashW(L"debugger")) {
                            match = TRUE;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    // Invalid pointer exception caught
                    KdPrint(("AtchKernel: Exception reading registry valueName.\n"));
                }

                if (match) {
                    UNICODE_STRING regPath;
                    RtlInitUnicodeString(&regPath, L"Registry\\IFEO");
                    NotifyViolationToRing3(0, &regPath, 1); // 1 could be REGISTRY_TAMPERING
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
                // simple case-insensitive check for csrss/lsass
                if (_stricmp(processName, "csrss.exe") == 0 || _stricmp(processName, "lsass.exe") == 0) {
                    isSystemProcess = TRUE;
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

// 4. Thread Callback (Anti-Remote Thread Injection)
void ThreadNotifyCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ThreadId);

    if (Create) {
        ULONG clientPid = GetExamClientProcessId();
        if (clientPid != 0 && ProcessId == (HANDLE)(ULONG_PTR)clientPid) {
            // Check if the thread is created by a different process
            HANDLE currentPid = PsGetCurrentProcessId();
            if (currentPid != (HANDLE)(ULONG_PTR)clientPid) {
                KdPrint(("AtchKernel: Remote thread injection blocked! Target: %lu, Creator: %lu\n", clientPid, (ULONG)(ULONG_PTR)currentPid));
                LockExam();
                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"Remote Thread Injection Blocked");
                NotifyViolationToRing3((ULONG)(ULONG_PTR)currentPid, &msg, 8); // 8: REMOTE_THREAD
            }
        }
    }
}

typedef struct _TERMINATION_WORK_ITEM_CONTEXT {
    WORK_QUEUE_ITEM WorkItem;
    HANDLE ProcessId;
    HANDLE ThreadId;
} TERMINATION_WORK_ITEM_CONTEXT, *PTERMINATION_WORK_ITEM_CONTEXT;

VOID TerminationWorkerRoutine(PVOID Context)
{
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
    ExFreePoolWithTag(pContext, 'mrTW');
}

void ForceKillExamProcess(HANDLE ProcessId)
{
    PTERMINATION_WORK_ITEM_CONTEXT pContext = (PTERMINATION_WORK_ITEM_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, sizeof(TERMINATION_WORK_ITEM_CONTEXT), 'mrTW');
    if (pContext != NULL) {
        pContext->ProcessId = ProcessId;
        pContext->ThreadId = NULL;
        ExInitializeWorkItem(&pContext->WorkItem, TerminationWorkerRoutine, pContext);
        ExQueueWorkItem(&pContext->WorkItem, DelayedWorkQueue);
    }
}

void ForceKillExamThread(HANDLE ProcessId, HANDLE ThreadId)
{
    PTERMINATION_WORK_ITEM_CONTEXT pContext = (PTERMINATION_WORK_ITEM_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, sizeof(TERMINATION_WORK_ITEM_CONTEXT), 'mrTW');
    if (pContext != NULL) {
        pContext->ProcessId = ProcessId;
        pContext->ThreadId = ThreadId;
        ExInitializeWorkItem(&pContext->WorkItem, TerminationWorkerRoutine, pContext);
        ExQueueWorkItem(&pContext->WorkItem, DelayedWorkQueue);
    }
}

NTSTATUS RegisterSecurityCallbacks(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;

    // Đăng ký Process Callback
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (NT_SUCCESS(status)) {
        g_ProcessCallbackRegistered = TRUE;
    }

    // Đăng ký Thread Callback
    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (NT_SUCCESS(status)) {
        g_ThreadCallbackRegistered = TRUE;
    }

    // Đăng ký Registry Callback
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"360000"); // Độ cao (Altitude) đăng ký
    status = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_RegistryCookie, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AtchKernel: Đăng ký Registry Callback thất bại.\n"));
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
        KdPrint(("AtchKernel: Đăng ký ObCallbacks thất bại.\n"));
    }

    return STATUS_SUCCESS;
}

void UnregisterSecurityCallbacks()
{
    if (g_ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
        g_ProcessCallbackRegistered = FALSE;
    }

    if (g_ThreadCallbackRegistered) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        g_ThreadCallbackRegistered = FALSE;
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
