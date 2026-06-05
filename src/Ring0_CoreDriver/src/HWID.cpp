#include "../inc/HWID.h"
#include <ntstrsafe.h>

#pragma pack(push, 1)
typedef struct _SMBIOS_HEADER {
    UCHAR Type;
    UCHAR Length;
    USHORT Handle;
} SMBIOS_HEADER, *PSMBIOS_HEADER;

typedef struct _SMBIOS_ENTRY_POINT {
    CHAR AnchorString[4]; // "_SM_"
    UCHAR Checksum;
    UCHAR Length;
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    USHORT MaxStructureSize;
    UCHAR EntryPointRevision;
    CHAR FormattedArea[5];
    CHAR IntermediateAnchorString[5]; // "_DMI_"
    UCHAR IntermediateChecksum;
    USHORT StructureTableLength;
    ULONG StructureTableAddress; // Physical Address
    USHORT NumberOfSMBIOSStructures;
    UCHAR BCDRevision;
} SMBIOS_ENTRY_POINT, *PSMBIOS_ENTRY_POINT;

typedef struct _SMBIOS_TYPE1 {
    SMBIOS_HEADER Header;
    UCHAR Manufacturer;
    UCHAR ProductName;
    UCHAR Version;
    UCHAR SerialNumber;
    UCHAR UUID[16];
    UCHAR WakeUpType;
    UCHAR SKUNumber;
    UCHAR Family;
} SMBIOS_TYPE1, *PSMBIOS_TYPE1;
#pragma pack(pop)

NTSTATUS GenerateHWID(PUNICODE_STRING HwidOut) {
    if (!HwidOut) return STATUS_INVALID_PARAMETER;

    NTSTATUS status = STATUS_NOT_FOUND;
    PHYSICAL_ADDRESS physAddr;
    physAddr.QuadPart = 0x000F0000;
    ULONG searchSize = 0x0000FFFF;

    PVOID memPtr = MmMapIoSpace(physAddr, searchSize, MmNonCached);
    if (!memPtr) return STATUS_INSUFFICIENT_RESOURCES;

    PSMBIOS_ENTRY_POINT smbiosEp = NULL;
    for (ULONG i = 0; i < searchSize; i += 16) {
        if (RtlCompareMemory((PUCHAR)memPtr + i, "_SM_", 4) == 4) {
            smbiosEp = (PSMBIOS_ENTRY_POINT)((PUCHAR)memPtr + i);
            break;
        }
    }

    if (smbiosEp) {
        PHYSICAL_ADDRESS tableAddr;
        tableAddr.QuadPart = smbiosEp->StructureTableAddress;
        PVOID tablePtr = MmMapIoSpace(tableAddr, smbiosEp->StructureTableLength, MmNonCached);
        
        if (tablePtr) {
            PUCHAR currentPtr = (PUCHAR)tablePtr;
            for (USHORT i = 0; i < smbiosEp->NumberOfSMBIOSStructures; i++) {
                PSMBIOS_HEADER header = (PSMBIOS_HEADER)currentPtr;
                if (header->Type == 1) { // System Information
                    PSMBIOS_TYPE1 type1 = (PSMBIOS_TYPE1)header;
                    
                    WCHAR uuidStr[64] = {0};
                    RtlStringCbPrintfW(uuidStr, sizeof(uuidStr), 
                        L"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                        type1->UUID[0], type1->UUID[1], type1->UUID[2], type1->UUID[3],
                        type1->UUID[4], type1->UUID[5], type1->UUID[6], type1->UUID[7],
                        type1->UUID[8], type1->UUID[9], type1->UUID[10], type1->UUID[11],
                        type1->UUID[12], type1->UUID[13], type1->UUID[14], type1->UUID[15]);

                    UNICODE_STRING uuidUs;
                    RtlInitUnicodeString(&uuidUs, uuidStr);

                    HwidOut->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPoolNx, uuidUs.MaximumLength, 'diWH');
                    if (HwidOut->Buffer) {
                        HwidOut->MaximumLength = uuidUs.MaximumLength;
                        HwidOut->Length = 0;
                        RtlCopyUnicodeString(HwidOut, &uuidUs);
                        status = STATUS_SUCCESS;
                    } else {
                        status = STATUS_INSUFFICIENT_RESOURCES;
                    }
                    break;
                }
                
                currentPtr += header->Length;
                while (*currentPtr != 0 || *(currentPtr + 1) != 0) {
                    currentPtr++;
                }
                currentPtr += 2;
            }
            MmUnmapIoSpace(tablePtr, smbiosEp->StructureTableLength);
        }
    }

    MmUnmapIoSpace(memPtr, searchSize);

    if (!NT_SUCCESS(status)) {
        UNICODE_STRING dummyHwid = RTL_CONSTANT_STRING(L"HWID-FALLBACK");
        HwidOut->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPoolNx, dummyHwid.MaximumLength, 'diWH');
        if (HwidOut->Buffer) {
            HwidOut->MaximumLength = dummyHwid.MaximumLength;
            HwidOut->Length = 0;
            RtlCopyUnicodeString(HwidOut, &dummyHwid);
            status = STATUS_SUCCESS;
        }
    }

    return status;
}
