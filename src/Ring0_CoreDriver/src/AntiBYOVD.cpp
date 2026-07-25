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
        hash == CompileTimeHashW(L"capcom.sys") ||
        hash == CompileTimeHashW(L"dbutil_2_3.sys") ||
        hash == CompileTimeHashW(L"mhyprot2.sys") ||
        hash == CompileTimeHashW(L"cpuz141.sys") ||
        hash == CompileTimeHashW(L"cpuz143.sys") ||
        hash == CompileTimeHashW(L"winio64.sys") ||
        hash == CompileTimeHashW(L"vboxdrv.sys") ||
        hash == CompileTimeHashW(L"asio.sys") ||
        hash == CompileTimeHashW(L"atszio64.sys") ||
        hash == CompileTimeHashW(L"msio64.sys") ||
        hash == CompileTimeHashW(L"inpoutx64.sys") ||
        hash == CompileTimeHashW(L"rzpnk.sys") ||
        hash == CompileTimeHashW(L"kdmapper.sys") ||
        hash == CompileTimeHashW(L"zam64.sys") ||
        hash == CompileTimeHashW(L"blackbone.sys") ||
        hash == CompileTimeHashW(L"echodrv.sys") ||
        hash == CompileTimeHashW(L"ksdumper.sys") ||
        hash == CompileTimeHashW(L"phymem64.sys") ||
        hash == CompileTimeHashW(L"procexp152.sys") ||
        hash == CompileTimeHashW(L"ene.sys") ||
        hash == CompileTimeHashW(L"alcpu64.sys") ||
        hash == CompileTimeHashW(L"amsiflt.sys") ||
        hash == CompileTimeHashW(L"kprocesshacker.sys") ||
        hash == CompileTimeHashW(L"nvaud_cast.sys") ||
        hash == CompileTimeHashW(L"rwdrv.sys") ||
        hash == CompileTimeHashW(L"atillk64.sys") ||
        hash == CompileTimeHashW(L"inpout32.sys") ||
        hash == CompileTimeHashW(L"ntiodrv64.sys") ||
        hash == CompileTimeHashW(L"xhunter1.sys") ||
        hash == CompileTimeHashW(L"gmer.sys") ||
        // OMEGA-XVIII: Additional BYOVD drivers — actively exploited in APT/ransomware
        hash == CompileTimeHashW(L"dbutil_2_5.sys") ||      // Dell BIOS v2.5 — CVE-2021-21551
        hash == CompileTimeHashW(L"aswarpot.sys") ||         // Avast Anti-Rootkit — Cuba/AvosLocker ransomware
        hash == CompileTimeHashW(L"mhyprot.sys") ||          // miHoYo v1
        hash == CompileTimeHashW(L"winring0x64.sys") ||      // WinRing0 — MSR/physical memory R/W
        hash == CompileTimeHashW(L"cpuz149.sys") ||          // CPUID v149
        hash == CompileTimeHashW(L"cpuz153.sys") ||          // CPUID v153
        hash == CompileTimeHashW(L"bs_rcio64.sys") ||        // Biostar — physical memory R/W
        hash == CompileTimeHashW(L"viragt64.sys") ||         // TrendMicro — kernel R/W
        hash == CompileTimeHashW(L"speedfan.sys") ||         // SpeedFan — physical memory
        hash == CompileTimeHashW(L"directio64.sys") ||       // DirectIO — hardware access
        hash == CompileTimeHashW(L"elrawdsk.sys") ||         // EldoS RawDisk — Shamoon/Destover
        hash == CompileTimeHashW(L"nvflash.sys")) {
        
        AtchPrint(("AtchKernel: BYOVD detected via hash!\n"));
        return TRUE;
    }

    return FALSE;
}

#ifdef __cplusplus
}
#endif
