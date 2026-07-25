#include "../inc/InputBlocker.h"
#include "../inc/IoctlHandler.h"
#include <ntifs.h>
#include <wdm.h>
#include <ntintsafe.h>
#include <intrin.h>

extern "C" NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID *Object
);
extern "C" POBJECT_TYPE* IoDriverObjectType;

#define FIDO_MAGIC 'FIDO'

typedef struct _FILTER_EXTENSION {
    ULONG Magic;
    PDEVICE_OBJECT FilterDevice;
    PDEVICE_OBJECT TargetDevice;
    PDEVICE_OBJECT LowerDevice;
    BOOLEAN IsKeyboard;
    IO_REMOVE_LOCK RemoveLock;
    LIST_ENTRY ListEntry;
} FILTER_EXTENSION, *PFILTER_EXTENSION;

static PDRIVER_OBJECT g_MyDriverObject = NULL;
static PDRIVER_DISPATCH g_OriginalWdfDispatch[IRP_MJ_MAXIMUM_FUNCTION + 1] = {0};
static volatile LONG g_DispatchHooked = 0;

static LIST_ENTRY g_FiDOList;
static KSPIN_LOCK g_FiDOListLock;

static NTSTATUS FilterReadCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }

    if (NT_SUCCESS(Irp->IoStatus.Status)) {
        if (IsExamLocked()) {
            // Validate Information against actual buffer length to prevent memory corruption
            PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
            ULONG readLen = stack->Parameters.Read.Length;
            ULONG_PTR infoLen = Irp->IoStatus.Information;
            if (infoLen > readLen) {
                infoLen = readLen; // Trust the original request size, not the lower driver
            }

            if (Irp->AssociatedIrp.SystemBuffer && infoLen > 0) {
                RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, infoLen);
            }

            // Also zero the MDL buffer for DO_DIRECT_IO devices
            if (Irp->MdlAddress != NULL && infoLen > 0) {
                // OMEGA-II M04: HighPagePriority at DISPATCH_LEVEL prevents fail-open under memory pressure
                PVOID mdlBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority | MdlMappingNoExecute);
                if (mdlBuffer) {
                    RtlZeroMemory(mdlBuffer, infoLen);
                } else {
                    // Fail-Safe: Nếu cạn kiệt bộ nhớ không thể zero đệm, ta buộc phải drop dữ liệu
                    Irp->IoStatus.Information = 0;
                    Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                }
            }
        }
    }

    // Release the remove lock acquired in FilterDispatchRead
    if (DeviceObject->DeviceExtension) {
        PFILTER_EXTENSION ext = (PFILTER_EXTENSION)DeviceObject->DeviceExtension;
        if (ext->Magic == FIDO_MAGIC) {
            IoReleaseRemoveLock(&ext->RemoveLock, Irp);
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS FilterDispatchPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (DeviceObject->DeviceExtension) {
        PFILTER_EXTENSION ext = (PFILTER_EXTENSION)DeviceObject->DeviceExtension;
        if (ext->Magic == FIDO_MAGIC) {
            NTSTATUS lockStatus = IoAcquireRemoveLock(&ext->RemoveLock, Irp);
            if (!NT_SUCCESS(lockStatus)) {
                // OMEGA-VI-POWER-01: Must start next power IRP even on remove lock failure
                PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
                if (stack->MajorFunction == IRP_MJ_POWER) {
                    PoStartNextPowerIrp(Irp);
                }
                Irp->IoStatus.Status = lockStatus;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return lockStatus;
            }

            PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

            // OMEGA-V-FILTER-02: Handle PnP REMOVE_DEVICE to prevent BSOD on USB keyboard unplug.
            // Without this, unplugging a USB keyboard leaves a dangling filter device.
            if (stack->MajorFunction == IRP_MJ_PNP &&
                stack->MinorFunction == IRP_MN_REMOVE_DEVICE) {
                
                // OMEGA-XVI CRIT-01: Release the initial NULL-tagged lock (from AttachToDevice)
                // BEFORE IoReleaseRemoveLockAndWait. Without this, the Wait will hang forever
                // because the NULL-tagged lock is never released in the PnP path.
                IoReleaseRemoveLock(&ext->RemoveLock, NULL);
                
                // OMEGA-VII-PNP-01: Now release the IRP-tagged lock and wait for all others.
                IoReleaseRemoveLockAndWait(&ext->RemoveLock, Irp);

                IoSkipCurrentIrpStackLocation(Irp);
                NTSTATUS pnpStatus = IoCallDriver(ext->LowerDevice, Irp);

                // OMEGA-VII-R1-001: Atomically remove from list AND invalidate magic
                // under spinlock to prevent double-remove race with UninitializeInputBlocker.
                KIRQL oldIrql;
                KeAcquireSpinLock(&g_FiDOListLock, &oldIrql);
                RemoveEntryList(&ext->ListEntry);
                // Poison the list entry to make any second RemoveEntryList crash-safe
                ext->ListEntry.Flink = NULL;
                ext->ListEntry.Blink = NULL;
                ext->Magic = 0; // Invalidate before releasing lock
                KeReleaseSpinLock(&g_FiDOListLock, oldIrql);

                // Detach and delete the filter device
                IoDetachDevice(ext->LowerDevice);
                ext->LowerDevice = NULL;
                IoDeleteDevice(DeviceObject);

                return pnpStatus;
            }

            IoSkipCurrentIrpStackLocation(Irp);

            // Power IRPs require special handling
            if (stack->MajorFunction == IRP_MJ_POWER) {
                PoStartNextPowerIrp(Irp);
                IoReleaseRemoveLock(&ext->RemoveLock, Irp);
                return PoCallDriver(ext->LowerDevice, Irp);
            } else {
                IoReleaseRemoveLock(&ext->RemoveLock, Irp);
                return IoCallDriver(ext->LowerDevice, Irp);
            }
        }
    }

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    UCHAR major = stack->MajorFunction;

    // OMEGA-XX CRITICAL: Bounds check to prevent OOB read + indirect call.
    // MajorFunction is UCHAR (0-255) but g_OriginalWdfDispatch only has
    // IRP_MJ_MAXIMUM_FUNCTION+1 (28) entries. Without this check, an attacker
    // can craft an IRP with MajorFunction > 27 to read adjacent memory
    // (e.g. g_DispatchHooked) as a function pointer and execute it — instant
    // Ring 0 arbitrary code execution.
    if (major > IRP_MJ_MAXIMUM_FUNCTION) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // OMEGA-FINAL HIGH-01: Spectre v1 fence — prevents speculative OOB read
    // of g_OriginalWdfDispatch[major] and speculative indirect call (Ring 0 RCE).
    _mm_lfence();

    if (g_OriginalWdfDispatch[major]) {
        return g_OriginalWdfDispatch[major](DeviceObject, Irp);
    }

    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS FilterDispatchRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (DeviceObject->DeviceExtension) {
        PFILTER_EXTENSION ext = (PFILTER_EXTENSION)DeviceObject->DeviceExtension;
        if (ext->Magic == FIDO_MAGIC) {
            // Acquire remove lock to prevent teardown while IRP is in flight
            NTSTATUS lockStatus = IoAcquireRemoveLock(&ext->RemoveLock, Irp);
            if (!NT_SUCCESS(lockStatus)) {
                // OMEGA-VI-POWER-01: Must start next power IRP even on remove lock failure
                PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
                if (stack->MajorFunction == IRP_MJ_POWER) {
                    PoStartNextPowerIrp(Irp);
                }
                Irp->IoStatus.Status = lockStatus;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return lockStatus;
            }

            IoCopyCurrentIrpStackLocationToNext(Irp);
            IoSetCompletionRoutine(Irp, FilterReadCompletion, NULL, TRUE, TRUE, TRUE);
            return IoCallDriver(ext->LowerDevice, Irp);
        }
    }

    if (g_OriginalWdfDispatch[IRP_MJ_READ]) {
        return g_OriginalWdfDispatch[IRP_MJ_READ](DeviceObject, Irp);
    }

    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS AttachToDevice(PDEVICE_OBJECT TargetDevice, BOOLEAN IsKeyboard)
{
    NTSTATUS status;
    PDEVICE_OBJECT filterDevice = NULL;

    status = IoCreateDevice(
        g_MyDriverObject,
        sizeof(FILTER_EXTENSION),
        NULL,
        TargetDevice->DeviceType,
        TargetDevice->Characteristics,
        FALSE,
        &filterDevice
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    PFILTER_EXTENSION ext = (PFILTER_EXTENSION)filterDevice->DeviceExtension;
    RtlZeroMemory(ext, sizeof(FILTER_EXTENSION));
    ext->Magic = FIDO_MAGIC;
    ext->FilterDevice = filterDevice;
    ext->TargetDevice = TargetDevice;
    ext->IsKeyboard = IsKeyboard;

    IoInitializeRemoveLock(&ext->RemoveLock, FIDO_MAGIC, 0, 0);

    // OMEGA-FINAL HIGH-07: Acquire remove lock with NULL tag to match
    // IoReleaseRemoveLockAndWait(NULL) during teardown. Without this,
    // Driver Verifier will BSOD on tag mismatch.
    // OMEGA-XVII: Check return — if device already removing, abort attach.
    NTSTATUS lockStatus = IoAcquireRemoveLock(&ext->RemoveLock, NULL);
    if (!NT_SUCCESS(lockStatus)) {
        IoDeleteDevice(filterDevice);
        return lockStatus;
    }

    filterDevice->Flags |= (TargetDevice->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE));

    ext->LowerDevice = IoAttachDeviceToDeviceStack(filterDevice, TargetDevice);
    if (!ext->LowerDevice) {
        // OMEGA-II HIGH-01: Release remove lock before deleting device to prevent DV BSOD
        IoReleaseRemoveLock(&ext->RemoveLock, NULL);
        IoDeleteDevice(filterDevice);
        return STATUS_NO_SUCH_DEVICE;
    }

    filterDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_FiDOListLock, &oldIrql);
    InsertTailList(&g_FiDOList, &ext->ListEntry);
    KeReleaseSpinLock(&g_FiDOListLock, oldIrql);

    return STATUS_SUCCESS;
}

static NTSTATUS HookTargetDriver(PUNICODE_STRING DriverName, BOOLEAN IsKeyboard)
{
    NTSTATUS status;
    PDRIVER_OBJECT targetDriver = NULL;

    status = ObReferenceObjectByName(DriverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&targetDriver);
    if (!NT_SUCCESS(status) || !targetDriver) {
        return status;
    }

    ULONG numDevices = 0;
    IoEnumerateDeviceObjectList(targetDriver, NULL, 0, &numDevices);
    if (numDevices > 0) {
        ULONG bufferSize = 0;
        if (!NT_SUCCESS(RtlULongMult(numDevices, sizeof(PDEVICE_OBJECT), &bufferSize))) {
            ObDereferenceObject(targetDriver);
            return STATUS_INTEGER_OVERFLOW;
        }
        PDEVICE_OBJECT* devList = (PDEVICE_OBJECT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'tslD');
        if (devList) {
            status = IoEnumerateDeviceObjectList(targetDriver, devList, bufferSize, &numDevices);
            if (NT_SUCCESS(status)) {
                for (ULONG i = 0; i < numDevices; i++) {
                    // STATIC ANALYSIS FIX H01: Check AttachToDevice return value
                    NTSTATUS attachStatus = AttachToDevice(devList[i], IsKeyboard);
                    if (!NT_SUCCESS(attachStatus)) {
                        AtchPrint(("AtchKernel: AttachToDevice failed for device %u: 0x%08X\n", i, attachStatus));
                    }
                    ObDereferenceObject(devList[i]);
                }
            }
            ExFreePoolWithTag(devList, 'tslD');
        }
    }

    ObDereferenceObject(targetDriver);
    return STATUS_SUCCESS;
}
// File-scope init guard: accessible by both Init and Uninit functions
static volatile LONG g_InputBlockerInitialized = 0;

NTSTATUS InitializeInputBlocker()
{
    // Guard against double-init: prevents FiDO orphaning and reference leaks
    if (InterlockedCompareExchange(&g_InputBlockerInitialized, 1, 0) != 0) {
        return STATUS_ALREADY_REGISTERED;
    }

    NTSTATUS status;
    UNICODE_STRING myDriverName;

    InitializeListHead(&g_FiDOList);
    KeInitializeSpinLock(&g_FiDOListLock);

    RtlInitUnicodeString(&myDriverName, L"\\Driver\\AtchKernel");
    status = ObReferenceObjectByName(&myDriverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&g_MyDriverObject);
    if (!NT_SUCCESS(status) || !g_MyDriverObject) {
        InterlockedExchange(&g_InputBlockerInitialized, 0);
        return status;
    }

    // Atomic check-then-set: prevents race where two threads both see 0 and enter
    if (InterlockedCompareExchange(&g_DispatchHooked, 1, 0) == 0) {
        for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
            g_OriginalWdfDispatch[i] = g_MyDriverObject->MajorFunction[i];
            g_MyDriverObject->MajorFunction[i] = FilterDispatchPassThrough;
        }
        g_MyDriverObject->MajorFunction[IRP_MJ_READ] = FilterDispatchRead;
    }

    UNICODE_STRING kbdName;
    RtlInitUnicodeString(&kbdName, L"\\Driver\\Kbdclass");
    // STATIC ANALYSIS FIX H02: Check HookTargetDriver return values
    NTSTATUS kbdStatus = HookTargetDriver(&kbdName, TRUE);
    if (!NT_SUCCESS(kbdStatus)) {
        AtchPrint(("AtchKernel: HookTargetDriver(Keyboard) failed: 0x%08X\n", kbdStatus));
    }

    UNICODE_STRING mouName;
    RtlInitUnicodeString(&mouName, L"\\Driver\\Mouclass");
    NTSTATUS mouStatus = HookTargetDriver(&mouName, FALSE);
    if (!NT_SUCCESS(mouStatus)) {
        AtchPrint(("AtchKernel: HookTargetDriver(Mouse) failed: 0x%08X\n", mouStatus));
    }

    return STATUS_SUCCESS;
}

void UninitializeInputBlocker()
{
    KIRQL oldIrql;
    
    // Check if list was initialized
    if (g_FiDOList.Flink == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_FiDOListLock, &oldIrql);
    while (!IsListEmpty(&g_FiDOList)) {
        PLIST_ENTRY listEntry = RemoveHeadList(&g_FiDOList);
        KeReleaseSpinLock(&g_FiDOListLock, oldIrql);

        PFILTER_EXTENSION ext = CONTAINING_RECORD(listEntry, FILTER_EXTENSION, ListEntry);

        // Wait for all outstanding IRPs to complete before teardown
        IoReleaseRemoveLockAndWait(&ext->RemoveLock, NULL);

        if (ext->LowerDevice) {
            IoDetachDevice(ext->LowerDevice);
        }
        if (ext->FilterDevice) {
            IoDeleteDevice(ext->FilterDevice);
        }

        KeAcquireSpinLock(&g_FiDOListLock, &oldIrql);
    }
    KeReleaseSpinLock(&g_FiDOListLock, oldIrql);

    if (InterlockedOr(&g_DispatchHooked, 0) != 0 && g_MyDriverObject) {
        for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
            g_MyDriverObject->MajorFunction[i] = g_OriginalWdfDispatch[i];
        }
        InterlockedExchange(&g_DispatchHooked, 0);
    }

    // OMEGA-II L03: Atomic exchange prevents dangling pointer between ObDeref and NULL assignment
    PDRIVER_OBJECT drvObj = (PDRIVER_OBJECT)InterlockedExchangePointer(
        (PVOID volatile*)&g_MyDriverObject, NULL);
    if (drvObj) {
        ObDereferenceObject(drvObj);
    }

    // Reset init guard to allow re-initialization after teardown
    InterlockedExchange(&g_InputBlockerInitialized, 0);
}
