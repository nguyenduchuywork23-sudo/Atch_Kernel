#include "../inc/HWID.h"

NTSTATUS GenerateHWID(PUNICODE_STRING HwidOut) {
    if (!HwidOut) {
        return STATUS_INVALID_PARAMETER;
    }

    // In a full implementation, we would query SMBIOS, drive serials, CPU id, etc.
    // For now, we provide a mock implementation as requested.
    UNICODE_STRING dummyHwid = RTL_CONSTANT_STRING(L"HWID-1234-ABCD-MOCK");

    HwidOut->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPoolNx, dummyHwid.MaximumLength, 'diWH');
    if (!HwidOut->Buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    HwidOut->MaximumLength = dummyHwid.MaximumLength;
    HwidOut->Length = 0; // RtlCopyUnicodeString will set the length

    RtlCopyUnicodeString(HwidOut, &dummyHwid);

    return STATUS_SUCCESS;
}
