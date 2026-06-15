#include "../inc/AntiBYOVD.h"
#include "../inc/CompileTimeHash.h"
#include "../inc/IoctlHandler.h"

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN IsVulnerableDriverLoaded(PUNICODE_STRING DriverName) {
    if (!DriverName || !DriverName->Buffer || DriverName->Length == 0) {
        return FALSE;
    }

    // Extract filename from full path, supporting both backslash and forward slash
    USHORT lastSlashPos = 0;
    USHORT wcharsCount = DriverName->Length / sizeof(WCHAR);
    for (USHORT i = 0; i < wcharsCount; i++) {
        if (DriverName->Buffer[i] == L'\\' || DriverName->Buffer[i] == L'/') {
            lastSlashPos = i + 1;
        }
    }

    UNICODE_STRING fileName;
    fileName.Buffer = &DriverName->Buffer[lastSlashPos];
    fileName.Length = DriverName->Length - (lastSlashPos * sizeof(WCHAR));
    
    // Remove trailing null terminator if present to prevent hash mismatch
    if (fileName.Length >= sizeof(WCHAR) && fileName.Buffer[(fileName.Length / sizeof(WCHAR)) - 1] == L'\0') {
        fileName.Length -= sizeof(WCHAR);
    }

    fileName.MaximumLength = fileName.Length;

    ULONG hash = RuntimeHashUnicodeString(&fileName);
    
    // Check against pre-calculated FNV-1a hashes of known BYOVDs
    if (hash == CompileTimeHashW(L"gdrv.sys") ||
        hash == CompileTimeHashW(L"rtcore64.sys") ||
        hash == CompileTimeHashW(L"iqvw64e.sys") ||
        hash == CompileTimeHashW(L"capcom.sys")) {
        
        AtchPrint(("AtchKernel: BYOVD detected via hash!\n"));
        return TRUE;
    }

    return FALSE;
}

#ifdef __cplusplus
}
#endif
