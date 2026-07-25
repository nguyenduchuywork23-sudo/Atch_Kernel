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

// OMEGA-VI-KPTI-01: Updated CheckMsrLstarIntegrity to use dynamic baseline instead of hardcoded block
BOOLEAN CheckMsrLstarIntegrity() {
    ULONG64 baseline = InterlockedOr64((LONG64 volatile*)&g_BaselineMsrLstar, 0);
    if (baseline == 0) return TRUE; // Not initialized yet
    
    ULONG64 currentLstar = __readmsr(MSR_LSTAR);
    if (currentLstar != baseline) {
        AtchPrint(("AtchKernel: MSR_LSTAR HOOK DETECTED! Expected: 0x%llX, Got: 0x%llX\n", baseline, currentLstar));
        InterlockedExchange(&g_HypervisorDetected, 1);
        return FALSE;
    }
    return TRUE;
}

BOOLEAN DetectHypervisor() {
    // Initialize MSR_LSTAR baseline dynamically at load time
    InterlockedExchange64((LONG64 volatile*)&g_BaselineMsrLstar, (LONG64)__readmsr(MSR_LSTAR));
    
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
            // [OMEGA-X DELTA] Không return FALSE để tránh bypass spoofing. Cho phép rơi xuống RDTSC.
        }
        else if (RtlCompareMemory(sig, "VMwareVMware", 12) == 12 ||
            RtlCompareMemory(sig, "KVMKVMKVM\0\0\0", 12) == 12 ||
            RtlCompareMemory(sig, "XenVMMXenVMM", 12) == 12 ||
            RtlCompareMemory(sig, "prl hyperv  ", 12) == 12 ||
            RtlCompareMemory(sig, "VBoxVBoxVBox", 12) == 12) {
            AtchPrint(("AtchKernel: Hypervisor signature detected: %.12s\n", sig));
            InterlockedExchange(&g_HypervisorDetected, 1);
            return TRUE;
        }
        else {
            // Unknown hypervisor with bit 31 set — suspicious
            AtchPrint(("AtchKernel: Unknown hypervisor detected (sig: %.12s). Flagging.\n", sig));
            InterlockedExchange(&g_HypervisorDetected, 1);
            return TRUE;
        }
    }


    // 3. RDTSC Timing Attack (VM-Exit Delay)
    // OMEGA-XXIII: Check CPUID support for RDTSCP to prevent #UD BSOD on older CPUs
    // OMEGA-XXVI: First verify CPU supports extended CPUID leaves before querying 0x80000001
    int maxExtInfo[4] = {0};
    __cpuid(maxExtInfo, (int)0x80000000);
    BOOLEAN hasExtendedLeaf = ((ULONG)maxExtInfo[0] >= 0x80000001);
    BOOLEAN hasRdtscp = FALSE;
    if (hasExtendedLeaf) {
    int rdtscpInfo[4] = {0};
    __cpuid(rdtscpInfo, (int)0x80000001);
    hasRdtscp = ((rdtscpInfo[3] & (1u << 27)) != 0);
    }

    ULONG detectedCount = 0;
    for (int i = 0; i < 10; ++i) {
        ULONG64 tsc1, tsc2;
        unsigned int aux = 0;
        
        KIRQL oldIrql;
        // OMEGA-XXVI: Runtime IRQL guard — NT_ASSERT is no-op in Release builds,
        // so add real check to prevent BSoD if called at IRQL > DISPATCH_LEVEL
        if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
            AtchPrint(("AtchKernel: DetectHypervisor RDTSC skipped — IRQL too high (%d).\n", KeGetCurrentIrql()));
            return FALSE;
        }
        KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
        
        volatile int timingCpuInfo[4] = {0};
        __cpuid((int*)timingCpuInfo, 0); // Serialize instruction pipeline
        tsc1 = hasRdtscp ? __rdtscp(&aux) : __rdtsc();
        __cpuid((int*)timingCpuInfo, 0); // Forces VM-Exit — volatile prevents dead code elimination
        tsc2 = hasRdtscp ? __rdtscp(&aux) : __rdtsc();
        
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

