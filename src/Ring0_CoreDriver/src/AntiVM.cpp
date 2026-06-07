#include "../inc/AntiVM.h"
#include "../inc/IoctlHandler.h"
#include <intrin.h>
#include <ntstrsafe.h>

BOOLEAN DetectHypervisor() {
    int cpuInfo[4] = {0};
    
    // 1. CPUID Leaf 1 (Basic check)
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] & (1 << 31)) != 0) {
        KdPrint(("AtchKernel: Hypervisor bit set in CPUID leaf 1.\n"));
        LockExam();
        return TRUE;
    }

    // 2. CPUID Leaf 0x40000000 (Hypervisor Signature)
    __cpuid(cpuInfo, 0x40000000);
    
    char sig[13] = {0};
    *(int*)(&sig[0]) = cpuInfo[1];
    *(int*)(&sig[4]) = cpuInfo[2];
    *(int*)(&sig[8]) = cpuInfo[3];
    
    // Note: Use RtlCompareMemory or simple strstr to find known VM signatures
    // For military grade, we shouldn't rely on string matching alone, but it's a good secondary check
    if (strstr(sig, "VMware") || strstr(sig, "KVM") || strstr(sig, "Microsoft Hv") || strstr(sig, "XenVMM") || strstr(sig, "prl hyperv")) {
        KdPrint(("AtchKernel: Hypervisor signature detected: %s\n", sig));
        LockExam();
        return TRUE;
    }

    // 3. RDTSC Timing Attack (VM-Exit Delay)
    // Run multiple times to avoid false positives from hardware interrupts
    ULONG detectedCount = 0;
    for (int i = 0; i < 10; ++i) {
        ULONG64 tsc1, tsc2;
        
        // Disable interrupts to get an accurate reading (Requires IRQL = HIGH_LEVEL or just use KeRaiseIrql)
        KIRQL oldIrql;
        KeRaiseIrql(HIGH_LEVEL, &oldIrql);
        
        tsc1 = __rdtsc();
        __cpuid(cpuInfo, 0); // Forces VM-Exit
        tsc2 = __rdtsc();
        
        KeLowerIrql(oldIrql);

        // A native CPUID usually takes < 500 cycles. A VM-Exit takes 1500+ cycles.
        if ((tsc2 - tsc1) > 1000) {
            detectedCount++;
        }
    }

    if (detectedCount >= 8) {
        KdPrint(("AtchKernel: RDTSC Timing anomaly detected (%lu/10). Possible VM.\n", detectedCount));
        LockExam();
        return TRUE;
    }
    
    KdPrint(("AtchKernel: No hypervisor detected.\n"));
    return FALSE;
}
