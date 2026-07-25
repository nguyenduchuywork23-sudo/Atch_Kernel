#pragma once

#ifndef DMA_PROTECTION_H
#define DMA_PROTECTION_H

#include <ntifs.h>
#include <wdf.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the DMA Protection module (Detect IOMMU, register PnP)
NTSTATUS InitDmaProtection(PDRIVER_OBJECT DriverObject);

// Cleanup the DMA Protection module
void UninitDmaProtection(VOID);

// Returns TRUE if IOMMU (VT-d/AMD-Vi) is active on the system
BOOLEAN IsDmaProtectionActive(VOID);

// Check for existing unauthorized DMA devices on Thunderbolt/PCIe buses
// Should be called periodically from the heartbeat thread
void CheckDmaThreats(VOID);

#ifdef __cplusplus
}
#endif

#endif // DMA_PROTECTION_H
