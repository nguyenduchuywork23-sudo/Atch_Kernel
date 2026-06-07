#include "../inc/InputBlocker.h"
#include "../inc/IoctlHandler.h"
#include <ntddk.h>
#include <wdm.h>

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
            if (Irp->AssociatedIrp.SystemBuffer && Irp->IoStatus.Information > 0) {
                RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, Irp->IoStatus.Information);
            }

            // Also zero the MDL buffer for DO_DIRECT_IO devices
            if (Irp->MdlAddress != NULL && Irp->IoStatus.Information > 0) {
                PVOID mdlBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
                if (mdlBuffer) {
                    RtlZeroMemory(mdlBuffer, Irp->IoStatus.Information);
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
                Irp->IoStatus.Status = lockStatus;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return lockStatus;
            }

            PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
            IoSkipCurrentIrpStackLocation(Irp);

            NTSTATUS status;
            // Power IRPs require special handling
            if (stack->MajorFunction == IRP_MJ_POWER) {
                PoStartNextPowerIrp(Irp);
                status = PoCallDriver(ext->LowerDevice, Irp);
            } else {
                status = IoCallDriver(ext->LowerDevice, Irp);
            }

            IoReleaseRemoveLock(&ext->RemoveLock, Irp);
            return status;
        }
    }

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    UCHAR major = stack->MajorFunction;
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

    filterDevice->Flags |= (TargetDevice->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE));

    ext->LowerDevice = IoAttachDeviceToDeviceStack(filterDevice, TargetDevice);
    if (!ext->LowerDevice) {
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
        ULONG bufferSize = numDevices * sizeof(PDEVICE_OBJECT);
        PDEVICE_OBJECT* devList = (PDEVICE_OBJECT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'tslD');
        if (devList) {
            status = IoEnumerateDeviceObjectList(targetDriver, devList, bufferSize, &numDevices);
            if (NT_SUCCESS(status)) {
                for (ULONG i = 0; i < numDevices; i++) {
                    AttachToDevice(devList[i], IsKeyboard);
                    ObDereferenceObject(devList[i]);
                }
            }
            ExFreePoolWithTag(devList, 'tslD');
        }
    }

    ObDereferenceObject(targetDriver);
    return STATUS_SUCCESS;
}

NTSTATUS InitializeInputBlocker()
{
    NTSTATUS status;
    UNICODE_STRING myDriverName;

    InitializeListHead(&g_FiDOList);
    KeInitializeSpinLock(&g_FiDOListLock);

    RtlInitUnicodeString(&myDriverName, L"\\Driver\\AtchKernel");
    status = ObReferenceObjectByName(&myDriverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&g_MyDriverObject);
    if (!NT_SUCCESS(status) || !g_MyDriverObject) {
        return status;
    }

    if (InterlockedOr(&g_DispatchHooked, 0) == 0) {
        for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
            g_OriginalWdfDispatch[i] = g_MyDriverObject->MajorFunction[i];
            g_MyDriverObject->MajorFunction[i] = FilterDispatchPassThrough;
        }
        g_MyDriverObject->MajorFunction[IRP_MJ_READ] = FilterDispatchRead;
        InterlockedExchange(&g_DispatchHooked, 1);
    }

    UNICODE_STRING kbdName;
    RtlInitUnicodeString(&kbdName, L"\\Driver\\Kbdclass");
    HookTargetDriver(&kbdName, TRUE);

    UNICODE_STRING mouName;
    RtlInitUnicodeString(&mouName, L"\\Driver\\Mouclass");
    HookTargetDriver(&mouName, FALSE);

    return STATUS_SUCCESS;
}

void UninitializeInputBlocker()
{
    KIRQL oldIrql;
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

    if (g_MyDriverObject) {
        ObDereferenceObject(g_MyDriverObject);
        g_MyDriverObject = NULL;
    }
}
