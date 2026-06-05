#include "../inc/AntiBYOVD.h"

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN IsVulnerableDriverLoaded(PUNICODE_STRING DriverName) {
    if (!DriverName || !DriverName->Buffer) {
        return FALSE;
    }

    static const PCWSTR VulnerableDrivers[] = {
        L"gdrv.sys",
        L"RTCore64.sys"
    };

    UNICODE_STRING VulnDriverString;
    const ULONG NumVulnerableDrivers = sizeof(VulnerableDrivers) / sizeof(VulnerableDrivers[0]);

    for (ULONG i = 0; i < NumVulnerableDrivers; ++i) {
        RtlInitUnicodeString(&VulnDriverString, VulnerableDrivers[i]);

        if (RtlCompareUnicodeString(DriverName, &VulnDriverString, TRUE) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

#ifdef __cplusplus
}
#endif
