#include "Callbacks.h"
#include "IoctlHandler.h"

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
        // Tiến trình đang được tạo
        // Mẫu: Phát hiện tiến trình đen (ví dụ "CheatEngine.exe")
        // Ở code thật sẽ có một cấu trúc Whitelist/Blacklist để kiểm tra.
        // Đây là code minh họa chặn và báo cáo về Ring 3
        
        if (CreateInfo->ImageFileName != NULL) {
            // Ví dụ logic blacklist giả định
            // Nếu phát hiện gian lận:
            // CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            // NotifyViolationToRing3((ULONG)(ULONG_PTR)ProcessId, CreateInfo->ImageFileName->Buffer, 2);
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
            // Lấy tên khóa Registry (đòi hỏi code phân tích phức tạp hơn bằng ObQueryNameString)
            // Nếu phát hiện nhánh Registry cấm -> trả về STATUS_ACCESS_DENIED
            // Đồng thời kích hoạt Alert về Ring 3: NotifyViolationToRing3(0, L"Registry\\IFEO", 1);
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

    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    // Nếu tiến trình bị truy cập là Client Ring 3 (được lưu trong ClientProcessId khi Handshake)
    // Code thực tế sẽ lấy EPROCESS của ClientProcessId và so sánh với OperationInformation->Object
    
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ||
        OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) 
    {
        ACCESS_MASK* pAccessBits = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            pAccessBits = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        }

        // Tước quyền Terminate, VM_WRITE, VM_READ để bảo vệ
        // *pAccessBits &= ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME);
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
