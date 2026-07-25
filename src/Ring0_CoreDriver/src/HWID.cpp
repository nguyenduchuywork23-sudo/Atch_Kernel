#include "../inc/HWID.h"

NTSTATUS GenerateHWID(PUNICODE_STRING HwidOut) {
    if (!HwidOut) {
        return STATUS_INVALID_PARAMETER;
    }

    // OMEGA-XVIII: Zero-initialize output to prevent caller from using garbage on error
    RtlZeroMemory(HwidOut, sizeof(UNICODE_STRING));

    // [OMEGA-X DELTA] HWID thực tế từ Registry:
    // HKLM\HARDWARE\DESCRIPTION\System\BIOS -> SystemSerialNumber (hoặc BaseBoardProduct nếu không có)
    UNICODE_STRING keyPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS");
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &objAttr);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UNICODE_STRING valName = RTL_CONSTANT_STRING(L"SystemSerialNumber");
    ULONG resultLength = 0;
    status = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &resultLength);
    
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        // Fallback to BaseBoardProduct
        RtlInitUnicodeString(&valName, L"BaseBoardProduct");
        status = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &resultLength);
    }

    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW && !NT_SUCCESS(status)) {
        ZwClose(hKey);
        return status;
    }

    PKEY_VALUE_PARTIAL_INFORMATION pKeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, resultLength, 'diWH');
    if (!pKeyInfo) {
        ZwClose(hKey);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, pKeyInfo, resultLength, &resultLength);
    // OMEGA-XVIII: Validate DataLength fits in USHORT and is at least sizeof(WCHAR)
    // to prevent kernel pool overflow (truncation) and integer underflow
    if (NT_SUCCESS(status) && pKeyInfo->Type == REG_SZ &&
        pKeyInfo->DataLength >= sizeof(WCHAR) && pKeyInfo->DataLength <= MAXUSHORT) {
        HwidOut->MaximumLength = (USHORT)pKeyInfo->DataLength;
        HwidOut->Length = HwidOut->MaximumLength - sizeof(WCHAR); // Exclude null terminator
        HwidOut->Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, HwidOut->MaximumLength, 'diWH');
        if (HwidOut->Buffer) {
            RtlCopyMemory(HwidOut->Buffer, pKeyInfo->Data, pKeyInfo->DataLength);
        } else {
            // OMEGA-XXI: Reset HwidOut to clean state on alloc failure
            // MaximumLength/Length were already set above — must clear for invariant:
            // "fail status ⟹ HwidOut completely clean"
            RtlZeroMemory(HwidOut, sizeof(UNICODE_STRING));
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    } else {
        status = STATUS_UNSUCCESSFUL;
    }

    ExFreePoolWithTag(pKeyInfo, 'diWH');
    ZwClose(hKey);
    return status;
}
