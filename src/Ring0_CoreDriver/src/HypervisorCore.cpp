#include "../inc/HypervisorCore.h"
#include <intrin.h>
#include "../../include/SharedDef.h"

static PVOID g_VmxonRegion = NULL;
static PHYSICAL_ADDRESS g_VmxonPhysicalAddress = { 0 };

BOOLEAN IsVirtualizationSupported() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    
    // Kiểm tra cờ VMX (Virtual Machine Extensions) ở thanh ghi ECX bit 5
    if ((cpuInfo[2] & (1 << 5)) == 0) {
        AtchPrint(("AtchKernel: [Hypervisor] CPU không hỗ trợ Intel VT-x (VMX)!\n"));
        return FALSE;
    }

    // Kiểm tra MSR IA32_FEATURE_CONTROL (0x3A) xem BIOS/UEFI có khóa Ảo hóa không
    // STATIC ANALYSIS FIX M05: Wrap in SEH — __readmsr can fault on VMs that trap this MSR
    __try {
        ULONG64 featureControl = __readmsr(0x3A);
        if ((featureControl & 1) == 0 || (featureControl & 4) == 0) {
            AtchPrint(("AtchKernel: [Hypervisor] VMX bị vô hiệu hóa trong BIOS/UEFI (IA32_FEATURE_CONTROL bị khóa)!\n"));
            return FALSE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        AtchPrint(("AtchKernel: [Hypervisor] __readmsr(0x3A) exception — MSR access restricted.\n"));
        return FALSE;
    }

    AtchPrint(("AtchKernel: [Hypervisor] CPU hỗ trợ VT-x. Sẵn sàng khởi động Ring -1.\n"));
    return TRUE;
}

NTSTATUS AllocateVmxonRegion() {
    PHYSICAL_ADDRESS highestAcceptable;
    highestAcceptable.QuadPart = ~0ULL; // Không giới hạn địa chỉ vật lý

    // OMEGA-VIII: Khởi tạo vùng nhớ liên tục cho Hypervisor để kháng DMA và Paging Exploits
    g_VmxonRegion = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE,
        { 0 },
        highestAcceptable,
        { 0 },
        MmCached
    );

    if (g_VmxonRegion == NULL) {
        AtchPrint(("AtchKernel: [Hypervisor] Không thể cấp phát bộ nhớ VMXON liên tục!\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlSecureZeroMemory(g_VmxonRegion, PAGE_SIZE);
    g_VmxonPhysicalAddress = MmGetPhysicalAddress(g_VmxonRegion);

    AtchPrint(("AtchKernel: [Hypervisor] Đã cấp phát VMXON Region tại Physical Address: 0x%llX\n", g_VmxonPhysicalAddress.QuadPart));
    return STATUS_SUCCESS;
}

NTSTATUS InitHypervisorCore() {
    AtchPrint(("AtchKernel: [Hypervisor] Đang khởi tạo nền tảng máy ảo Ring -1...\n"));

    if (!IsVirtualizationSupported()) {
        AtchPrint(("AtchKernel: [Hypervisor] Nền tảng không đủ điều kiện chạy Hypervisor!\n"));
        // Ta vẫn return SUCCESS để Driver Ring 0 hoạt động bình thường như một fallback
        return STATUS_SUCCESS; 
    }

    NTSTATUS status = AllocateVmxonRegion();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    AtchPrint(("AtchKernel: [Hypervisor] OMEGA-XV WARNING: VMXON Region allocated but VMX Root Mode is a STUB. Ring -1 protection is NOT active.\n"));
    return STATUS_SUCCESS;
}

// STATIC ANALYSIS FIX C02: Free VMXON contiguous memory region on driver unload.
// Without this, 4KB of physically contiguous memory is leaked per driver load.
void UninitHypervisorCore() {
    if (g_VmxonRegion != NULL) {
        RtlSecureZeroMemory(g_VmxonRegion, PAGE_SIZE); // Forensic scrub before free
        MmFreeContiguousMemory(g_VmxonRegion);
        g_VmxonRegion = NULL;
        g_VmxonPhysicalAddress.QuadPart = 0;
        AtchPrint(("AtchKernel: [Hypervisor] VMXON Region freed.\n"));
    }
}

