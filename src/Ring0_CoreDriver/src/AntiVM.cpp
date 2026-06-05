#include "../inc/AntiVM.h"

BOOLEAN DetectHypervisor() {
    int cpuInfo[4] = {0};
    
    // 1. Basic CPUID Check
    __cpuid(cpuInfo, 1);
    
    // The 31st bit of ECX indicates the presence of a hypervisor
    if ((cpuInfo[2] & (1 << 31)) != 0) {
        KdPrint(("Atch_Kernel: Hypervisor environment detected (CPUID bit).\n"));
        return TRUE;
    }
    
    // 2. Hypervisor Vendor Check
    __cpuid(cpuInfo, 0x40000000);
    char vendorId[13];
    RtlCopyMemory(vendorId, &cpuInfo[1], 4);       // EBX
    RtlCopyMemory(vendorId + 4, &cpuInfo[2], 4);   // ECX
    RtlCopyMemory(vendorId + 8, &cpuInfo[3], 4);   // EDX
    vendorId[12] = '\0';

    if (RtlCompareMemory(vendorId, "VMwareVMware", 12) == 12 ||
        RtlCompareMemory(vendorId, "VBoxVBoxVBox", 12) == 12 ||
        RtlCompareMemory(vendorId, "KVMKVMKVM\0\0\0", 12) == 12 ||
        RtlCompareMemory(vendorId, "Microsoft Hv", 12) == 12) {
        KdPrint(("Atch_Kernel: Hypervisor environment detected (Vendor: %s).\n", vendorId));
        return TRUE;
    }
    
    // 3. Timing Check (RDTSC)
    ULONG64 tsc1, tsc2;
    tsc1 = __rdtsc();
    
    // Force a VM exit via CPUID
    int temp[4];
    __cpuid(temp, 0);
    
    tsc2 = __rdtsc();
    
    // In a bare-metal environment, CPUID takes ~100-300 cycles.
    // In a VM, CPUID causes a VM-Exit which takes > 1000 cycles.
    if ((tsc2 - tsc1) > 1000) {
        KdPrint(("Atch_Kernel: Hypervisor environment detected (Timing anomaly: %llu cycles).\n", (tsc2 - tsc1)));
        return TRUE;
    }

    KdPrint(("Atch_Kernel: No hypervisor detected.\n"));
    return FALSE;
}
