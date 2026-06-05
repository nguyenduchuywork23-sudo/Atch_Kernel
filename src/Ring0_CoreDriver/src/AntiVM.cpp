#include "../inc/AntiVM.h"

BOOLEAN DetectHypervisor() {
    int cpuInfo[4] = {0};
    
    // CPUID with EAX = 1
    __cpuid(cpuInfo, 1);
    
    // The 31st bit of ECX indicates the presence of a hypervisor
    if ((cpuInfo[2] & (1 << 31)) != 0) {
        KdPrint(("AntiCheat: Hypervisor environment detected.\n"));
        return TRUE;
    }
    
    KdPrint(("AntiCheat: No hypervisor detected.\n"));
    return FALSE;
}
