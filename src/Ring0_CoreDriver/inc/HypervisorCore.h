#pragma once

#ifndef HYPERVISOR_CORE_H
#define HYPERVISOR_CORE_H

#include <ntifs.h>
#include <wdf.h>

#ifdef __cplusplus
extern "C" {
#endif

// Khởi tạo nền tảng Hypervisor (Ring -1)
NTSTATUS InitHypervisorCore(VOID);

// Kiểm tra phần cứng có hỗ trợ Ảo hóa hay không (Intel VT-x / AMD-V)
BOOLEAN IsVirtualizationSupported(VOID);

// Cấp phát vùng nhớ VMXON liên tục trong RAM vật lý
NTSTATUS AllocateVmxonRegion(VOID);

// STATIC ANALYSIS FIX C02: Giải phóng vùng nhớ VMXON khi Unload
void UninitHypervisorCore(VOID);

#ifdef __cplusplus
}
#endif

#endif // HYPERVISOR_CORE_H
