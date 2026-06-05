#include "../inc/LoadImageNotify.h"

void LoadImageNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);

    if (FullImageName != NULL)
    {
        KdPrint(("[Atch_Kernel] Image Loaded: %wZ\n", FullImageName));
    }
}

NTSTATUS InitLoadImageNotify(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    
    NTSTATUS status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (NT_SUCCESS(status))
    {
        KdPrint(("[Atch_Kernel] LoadImageNotify registered successfully.\n"));
    }
    else
    {
        KdPrint(("[Atch_Kernel] Failed to register LoadImageNotify. Status: 0x%X\n", status));
    }

    return status;
}

void UnloadImageNotify()
{
    NTSTATUS status = PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (NT_SUCCESS(status))
    {
        KdPrint(("[Atch_Kernel] LoadImageNotify unregistered successfully.\n"));
    }
    else
    {
        KdPrint(("[Atch_Kernel] Failed to unregister LoadImageNotify. Status: 0x%X\n", status));
    }
}
