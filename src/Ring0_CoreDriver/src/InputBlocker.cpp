#include "../inc/InputBlocker.h"
#include "../inc/IoctlHandler.h"

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

static PDRIVER_DISPATCH g_OriginalKbdRead = NULL;
static PDRIVER_DISPATCH g_OriginalMouRead = NULL;

static PDRIVER_OBJECT g_KbdDriverObject = NULL;
static PDRIVER_OBJECT g_MouDriverObject = NULL;

NTSTATUS HookedKbdRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (IsExamLocked()) {
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }
    return g_OriginalKbdRead(DeviceObject, Irp);
}

NTSTATUS HookedMouRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (IsExamLocked()) {
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }
    return g_OriginalMouRead(DeviceObject, Irp);
}

NTSTATUS InitializeInputBlocker()
{
    NTSTATUS status;
    UNICODE_STRING kbdName;
    UNICODE_STRING mouName;
    
    RtlInitUnicodeString(&kbdName, L"\\Driver\\Kbdclass");
    RtlInitUnicodeString(&mouName, L"\\Driver\\Mouclass");
    
    status = ObReferenceObjectByName(&kbdName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&g_KbdDriverObject);
    if (NT_SUCCESS(status) && g_KbdDriverObject != NULL) {
        g_OriginalKbdRead = (PDRIVER_DISPATCH)InterlockedExchangePointer((PVOID*)&g_KbdDriverObject->MajorFunction[IRP_MJ_READ], (PVOID)HookedKbdRead);
    }

    status = ObReferenceObjectByName(&mouName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&g_MouDriverObject);
    if (NT_SUCCESS(status) && g_MouDriverObject != NULL) {
        g_OriginalMouRead = (PDRIVER_DISPATCH)InterlockedExchangePointer((PVOID*)&g_MouDriverObject->MajorFunction[IRP_MJ_READ], (PVOID)HookedMouRead);
    }
    
    return STATUS_SUCCESS;
}

void UninitializeInputBlocker()
{
    if (g_KbdDriverObject && g_OriginalKbdRead) {
        InterlockedExchangePointer((PVOID*)&g_KbdDriverObject->MajorFunction[IRP_MJ_READ], (PVOID)g_OriginalKbdRead);
        ObDereferenceObject(g_KbdDriverObject);
        g_KbdDriverObject = NULL;
    }
    
    if (g_MouDriverObject && g_OriginalMouRead) {
        InterlockedExchangePointer((PVOID*)&g_MouDriverObject->MajorFunction[IRP_MJ_READ], (PVOID)g_OriginalMouRead);
        ObDereferenceObject(g_MouDriverObject);
        g_MouDriverObject = NULL;
    }
}
