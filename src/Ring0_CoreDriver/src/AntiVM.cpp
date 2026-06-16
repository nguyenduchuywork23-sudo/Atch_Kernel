#include "../inc/AntiVM.h"
#include "../inc/IoctlHandler.h"
#include <intrin.h>
#include <ntstrsafe.h>

// Persistent flag: survives across IOCTL calls, cannot be overwritten by INITIALIZE_EXAM
static volatile LONG g_HypervisorDetected = 0;

// OMEGA-XXV: MSR_LSTAR baseline for system call hook detection
#define MSR_LSTAR 0xC0000082
static volatile ULONG64 g_BaselineMsrLstar = 0;

BOOLEAN IsHypervisorDetected() {
    return (InterlockedOr(&g_HypervisorDetected, 0) != 0);
}

// OMEGA-VI-KPTI-01: Removed CheckMsrLstarIntegrity to prevent false-positives under KVA Shadow
BOOLEAN CheckMsrLstarIntegrity() {
    return TRUE; // Deprecated due to KPTI/HVCI false positives
}

BOOLEAN DetectHypervisor() {
    int cpuInfo[4] = {0};

    // 1. CPUID Leaf 1 (Basic check)
    __cpuid(cpuInfo, 1);
    BOOLEAN hypervisorBitSet = ((cpuInfo[2] & (1u << 31)) != 0);
    
    if (hypervisorBitSet) {
        // 2. CPUID Leaf 0x40000000 (Hypervisor Signature)
        // We MUST check the signature BEFORE flagging, to skip Microsoft Hv (VBS/HVCI)
        __cpuid(cpuInfo, 0x40000000);
        
        char sig[13] = {0};
        // OMEGA-XV: Use RtlCopyMemory instead of pointer cast to avoid strict aliasing violation
        RtlCopyMemory(&sig[0], &cpuInfo[1], 4);
        RtlCopyMemory(&sig[4], &cpuInfo[2], 4);
        RtlCopyMemory(&sig[8], &cpuInfo[3], 4);
        
        // Skip Microsoft Hv — this is Windows VBS/HVCI or Azure, NOT a cheating VM
        // On Windows 11 with default settings, VBS enables Hyper-V at firmware level
        // and sets CPUID bit 31 on BARE METAL hardware. Blocking this = mass false positive.
        if (RtlCompareMemory(sig, "Microsoft Hv", 12) == 12) {
            AtchPrint(("AtchKernel: Microsoft Hyper-V/VBS detected — ALLOWED (native Windows feature).\n"));
            return FALSE;
        }
        
        // Check for known VM signatures (non-Microsoft)
        if (RtlCompareMemory(sig, "VMwareVMware", 12) == 12 ||
            RtlCompareMemory(sig, "KVMKVMKVM\0\0\0", 12) == 12 ||
            RtlCompareMemory(sig, "XenVMMXenVMM", 12) == 12 ||
            RtlCompareMemory(sig, "prl hyperv  ", 12) == 12 ||
            RtlCompareMemory(sig, "VBoxVBoxVBox", 12) == 12) {
            AtchPrint(("AtchKernel: Hypervisor signature detected: %.12s\n", sig));
            InterlockedExchange(&g_HypervisorDetected, 1);
            return TRUE;
        }
        
        // Unknown hypervisor with bit 31 set — suspicious
        AtchPrint(("AtchKernel: Unknown hypervisor detected (sig: %.12s). Flagging.\n", sig));
        InterlockedExchange(&g_HypervisorDetected, 1);
        return TRUE;
    }

    // 3. RDTSC Timing Attack (VM-Exit Delay)
    ULONG detectedCount = 0;
    for (int i = 0; i < 10; ++i) {
        ULONG64 tsc1, tsc2;
        unsigned int aux = 0;
        
        KIRQL oldIrql;
        KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
        
        volatile int timingCpuInfo[4] = {0};
        __cpuid((int*)timingCpuInfo, 0); // Serialize instruction pipeline
        tsc1 = __rdtscp(&aux);
        __cpuid((int*)timingCpuInfo, 0); // Forces VM-Exit — volatile prevents dead code elimination
        tsc2 = __rdtscp(&aux);
        
        KeLowerIrql(oldIrql);

        // Native CPUID: < 500 cycles. VM-Exit: 1500+ cycles.
        if ((tsc2 - tsc1) > 1000) {
            detectedCount++;
        }
    }

    if (detectedCount >= 8) {
        AtchPrint(("AtchKernel: RDTSC Timing anomaly (%lu/10). Possible VM.\n", detectedCount));
        InterlockedExchange(&g_HypervisorDetected, 1);
        return TRUE;
    }
    
    AtchPrint(("AtchKernel: No hypervisor detected.\n"));
    return FALSE;
}

