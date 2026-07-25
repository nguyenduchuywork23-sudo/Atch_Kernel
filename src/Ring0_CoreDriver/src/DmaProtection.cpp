#include "../inc/DmaProtection.h"
#include "../../include/SharedDef.h"
#include "../inc/IoctlHandler.h"
#include <ntddk.h>
#include <wdmguid.h>

static volatile LONG g_IommuActive = 0;
static PVOID g_PnpNotificationEntry = NULL;

static void DetectIommuStatus() {
    // Check DmaRemappingCompatible in registry
    UNICODE_STRING keyName;
    RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control");
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    HANDLE keyHandle = NULL;
    NTSTATUS status = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING valueName;
        RtlInitUnicodeString(&valueName, L"DmaRemappingCompatible");
        
        UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
        PKEY_VALUE_PARTIAL_INFORMATION valueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
        ULONG resultLength = 0;
        
        status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, valueInfo, sizeof(buffer), &resultLength);
        if (NT_SUCCESS(status) && valueInfo->Type == REG_DWORD && valueInfo->DataLength == sizeof(ULONG)) {
            ULONG value = *((PULONG)valueInfo->Data);
            if (value != 0) {
                InterlockedExchange(&g_IommuActive, 1);
                AtchPrint(("AtchKernel: [DMA] IOMMU (VT-d/AMD-Vi) is ACTIVE.\n"));
            } else {
                AtchPrint(("AtchKernel: [DMA] IOMMU (VT-d/AMD-Vi) is DISABLED or not supported.\n"));
            }
        } else {
            AtchPrint(("AtchKernel: [DMA] DmaRemappingCompatible registry value not found.\n"));
        }
        ZwClose(keyHandle);
    } else {
        AtchPrint(("AtchKernel: [DMA] Failed to open Control registry key (Status: 0x%X)\n", status));
    }
}

static void EnforceDmaGuardPolicy() {
    UNICODE_STRING keyName;
    RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows\\Kernel DMA Protection");
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    HANDLE keyHandle = NULL;
    NTSTATUS status = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING valueName;
        RtlInitUnicodeString(&valueName, L"DeviceEnumerationPolicy");
        
        UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
        PKEY_VALUE_PARTIAL_INFORMATION valueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
        ULONG resultLength = 0;
        
        status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, valueInfo, sizeof(buffer), &resultLength);
        if (NT_SUCCESS(status) && valueInfo->Type == REG_DWORD && valueInfo->DataLength == sizeof(ULONG)) {
            ULONG policy = *((PULONG)valueInfo->Data);
            AtchPrint(("AtchKernel: [DMA] Kernel DMA Protection DeviceEnumerationPolicy = %lu\n", policy));
            if (policy == 0 || policy == 1) { // 0: Block All, 1: Block until login
                AtchPrint(("AtchKernel: [DMA] Kernel DMA Protection is enforcing security.\n"));
            } else {
                AtchPrint(("AtchKernel: [DMA] WARNING: DMA Guard policy allows external devices (Policy=%lu).\n", policy));
            }
        } else {
            AtchPrint(("AtchKernel: [DMA] DeviceEnumerationPolicy value not found.\n"));
        }
        ZwClose(keyHandle);
    } else {
        AtchPrint(("AtchKernel: [DMA] Kernel DMA Protection registry key not found (Status: 0x%X)\n", status));
    }
}

static NTSTATUS DmaPnpNotifyCallback(
    _In_ PVOID NotificationStructure,
    _Inout_opt_ PVOID Context
)
{
    UNREFERENCED_PARAMETER(Context);

    PDEVICE_INTERFACE_CHANGE_NOTIFICATION pnpEvent = (PDEVICE_INTERFACE_CHANGE_NOTIFICATION)NotificationStructure;
    
    // We only care about device arrival (hotplug)
    if (IsEqualGUID(pnpEvent->Event, GUID_DEVICE_INTERFACE_ARRIVAL)) {
        // If an exam is currently running, we should block or flag any new external DMA device
        ULONG examClientPid = GetExamClientProcessId();
        if (examClientPid != 0) {
            AtchPrint(("AtchKernel: [DMA] Hotplug device arrival detected during active exam: %wZ\n", pnpEvent->SymbolicLinkName));
            
            // To be aggressive but safe, we will flag this as a DMA attack violation
            LockExam();
            UNICODE_STRING msg;
            RtlInitUnicodeString(&msg, L"External Device Hotplug during Exam");
            NotifyViolationToRing3(examClientPid, &msg, ViolationType::VIOLATION_DMA_ATTACK);
        }
    }

    return STATUS_SUCCESS;
}

static const GUID GUID_DEVINTERFACE_USB_DEVICE_LOCAL = { 0xA5DCBF10L, 0x6530, 0x11D2, { 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED } };

NTSTATUS InitDmaProtection(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    AtchPrint(("AtchKernel: [DMA] Initializing DMA Protection module...\n"));

    DetectIommuStatus();
    EnforceDmaGuardPolicy();

    // Register PnP notification for general device interfaces to detect hotplugging
    NTSTATUS status = IoRegisterPlugPlayNotification(
        EventCategoryDeviceInterfaceChange,
        0,
        (PVOID)&GUID_DEVINTERFACE_USB_DEVICE_LOCAL, // We can monitor USB as a baseline, or specific PCIe GUIDs
        DriverObject,
        DmaPnpNotifyCallback,
        NULL,
        &g_PnpNotificationEntry
    );

    if (NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: [DMA] PnP Notification registered successfully.\n"));
    } else {
        AtchPrint(("AtchKernel: [DMA] Failed to register PnP notification (Status: 0x%X)\n", status));
    }

    return STATUS_SUCCESS;
}

void UninitDmaProtection() {
    if (g_PnpNotificationEntry != NULL) {
        IoUnregisterPlugPlayNotificationEx(g_PnpNotificationEntry);
        g_PnpNotificationEntry = NULL;
        AtchPrint(("AtchKernel: [DMA] PnP Notification unregistered.\n"));
    }
}

BOOLEAN IsDmaProtectionActive() {
    return InterlockedOr(&g_IommuActive, 0) != 0;
}

void CheckDmaThreats() {
    // OMEGA-XXVI: Real DMA threat scan — replaced stub with periodic IOMMU status re-check.
    // Re-check IOMMU status periodically to detect runtime DMA remapping disable.
    static volatile LONG g_DmaCheckCount = 0;
    LONG count = InterlockedIncrement(&g_DmaCheckCount);

    // Only re-check every 60 iterations (~1 minute at 1Hz heartbeat) to avoid overhead
    if ((count % 60) != 0) return;

    // If IOMMU was active at boot but is no longer, flag a threat
    if (InterlockedOr(&g_IommuActive, 0) != 0) {
        // Re-read the registry to see if DmaRemappingCompatible changed
        UNICODE_STRING keyName;
        RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control");
        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        HANDLE keyHandle = NULL;
        NTSTATUS status = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);
        if (NT_SUCCESS(status)) {
            UNICODE_STRING valueName;
            RtlInitUnicodeString(&valueName, L"DmaRemappingCompatible");

            UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
            PKEY_VALUE_PARTIAL_INFORMATION valueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
            ULONG resultLength = 0;

            status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation,
                                     valueInfo, sizeof(buffer), &resultLength);
            if (NT_SUCCESS(status) && valueInfo->Type == REG_DWORD &&
                valueInfo->DataLength == sizeof(ULONG)) {
                ULONG value = *((PULONG)valueInfo->Data);
                if (value == 0) {
                    AtchPrint(("AtchKernel: [DMA] CRITICAL - IOMMU was active at boot but registry now says DISABLED!\n"));
                    // Flag violation if exam is running
                    ULONG examPid = GetExamClientProcessId();
                    if (examPid != 0) {
                        LockExam();
                        UNICODE_STRING msg;
                        RtlInitUnicodeString(&msg, L"IOMMU DMA Protection Disabled During Exam");
                        NotifyViolationToRing3(examPid, &msg, ViolationType::VIOLATION_DMA_ATTACK);
                    }
                }
            }
            ZwClose(keyHandle);
        }
    }
}
