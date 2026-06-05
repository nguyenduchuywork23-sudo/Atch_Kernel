#include "../inc/LoadImageNotify.h"
#include "../inc/AntiBYOVD.h"

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
        
        // Kiểm tra xem có phải là driver có lỗ hổng (BYOVD) không
        if (ImageInfo != NULL && ImageInfo->SystemModeImage) {
            if (IsVulnerableDriverLoaded(FullImageName)) {
                KdPrint(("[Atch_Kernel] WARNING: Vulnerable Driver Detected (BYOVD): %wZ\n", FullImageName));
                // Tương lai: Có thể hook entry point để block hoặc set cờ báo về Ring 3
            }
        }
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
