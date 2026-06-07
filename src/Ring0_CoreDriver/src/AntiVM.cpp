#include "../inc/AntiVM.h"
#include "../inc/IoctlHandler.h"
#include <intrin.h>
#include <ntstrsafe.h>

BOOLEAN DetectHypervisor() {
    int cpuInfo[4] = {0};
    
    // 1. CPUID Leaf 1 (Basic check)
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] & (1u << 31)) != 0) {
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
    
    // Use RtlCompareMemory for kernel-mode safe string matching against known VM signatures
    if (RtlCompareMemory(sig, "VMwareVMware", 12) == 12 ||
        RtlCompareMemory(sig, "KVMKVMKVM\0\0\0", 12) == 12 ||
        RtlCompareMemory(sig, "Microsoft Hv", 12) == 12 ||
        RtlCompareMemory(sig, "XenVMMXenVMM", 12) == 12 ||
        RtlCompareMemory(sig, "prl hyperv ", 12) == 12) {
        KdPrint(("AtchKernel: Hypervisor signature detected: %s\n", sig));
        LockExam();
        return TRUE;
    }

    // 3. RDTSC Timing Attack (VM-Exit Delay)
    // Run multiple times to avoid false positives from hardware interrupts
    ULONG detectedCount = 0;
    for (int i = 0; i < 10; ++i) {
        ULONG64 tsc1, tsc2;
        unsigned int aux;
        
        // Disable interrupts to get an accurate reading (Requires IRQL = HIGH_LEVEL or just use KeRaiseIrql)
        KIRQL oldIrql;
        KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
        
        __cpuid(cpuInfo, 0); // Serialize instruction pipeline
        tsc1 = __rdtscp(&aux);
        __cpuid(cpuInfo, 0); // Forces VM-Exit
        tsc2 = __rdtscp(&aux);
        
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
