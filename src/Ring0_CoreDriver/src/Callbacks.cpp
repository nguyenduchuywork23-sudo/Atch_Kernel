#include "../inc/Callbacks.h"
#include "../inc/IoctlHandler.h"

// Biến lưu cookie đăng ký
static LARGE_INTEGER g_RegistryCookie = { 0 };
static PVOID g_ObRegistrationHandle = NULL;
static BOOLEAN g_ProcessCallbackRegistered = FALSE;

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
            // Basic blacklist
            PCUNICODE_STRING imageName = CreateInfo->ImageFileName;
            
            // Note: In a real implementation we would do a case-insensitive check and 
            // extract just the filename if the full path is provided.
            // For this example, we just check if it contains the blacklisted names.
            
            BOOLEAN isBlacklisted = FALSE;
            
            if (imageName->Buffer != NULL && imageName->Length > 0) {
                // Ensure null termination for safe search
                WCHAR safeBuffer[256];
                size_t bytesToCopy = imageName->Length;
                if (bytesToCopy > sizeof(safeBuffer) - sizeof(WCHAR)) {
                    bytesToCopy = sizeof(safeBuffer) - sizeof(WCHAR);
                }
                RtlCopyMemory(safeBuffer, imageName->Buffer, bytesToCopy);
                safeBuffer[bytesToCopy / sizeof(WCHAR)] = L'\0';

                UNICODE_STRING safeUs;
                RtlInitUnicodeString(&safeUs, safeBuffer);
                
                // Convert to lowercase for basic check
                for (USHORT i = 0; i < safeUs.Length / sizeof(WCHAR); i++) {
                    safeUs.Buffer[i] = RtlDowncaseUnicodeChar(safeUs.Buffer[i]);
                }

                if (wcsstr(safeUs.Buffer, L"cheatengine-x86_64.exe") != NULL ||
                    wcsstr(safeUs.Buffer, L"processhacker.exe") != NULL ||
                    wcsstr(safeUs.Buffer, L"ida64.exe") != NULL) {
                    isBlacklisted = TRUE;
                }

                if (isBlacklisted) {
                    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                    NotifyViolationToRing3((ULONG)(ULONG_PTR)ProcessId, &safeUs, 2); // 2 could be PROCESS_BLACKLISTED
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
            
            if (valueName != NULL && valueName->Buffer != NULL) {
                UNICODE_STRING targetName;
                RtlInitUnicodeString(&targetName, L"Debugger");
                // Compare accurately using RtlCompareUnicodeString which safely handles Length
                if (RtlCompareUnicodeString(valueName, &targetName, TRUE) == 0) {
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
            // Block modification if it's not a kernel handle
            if (!OperationInformation->KernelHandle) {
                if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME);
                } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                    OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME);
                }
            }
        }
        ObDereferenceObject(clientProcess);
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS RegisterSecurityCallbacks(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;

    // Đăng ký Process Callback
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (NT_SUCCESS(status)) {
        g_ProcessCallbackRegistered = TRUE;
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

    if (g_RegistryCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegistryCookie);
        g_RegistryCookie.QuadPart = 0;
    }

    if (g_ObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
    }
}
