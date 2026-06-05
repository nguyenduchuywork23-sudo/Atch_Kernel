#include <ntddk.h>
#include <wdf.h>
#include "../../include/SharedDef.h"
#include "../inc/IoctlHandler.h"
#include "../inc/Callbacks.h"
#include "../inc/AntiBYOVD.h"
#include "../inc/AntiVM.h"
#include "../inc/HWID.h"
#include "../inc/LoadImageNotify.h"
#include "../inc/ThreadNotify.h"

// Khai báo tên thiết bị và DOS device name
DECLARE_CONST_UNICODE_STRING(ntDeviceName, L"\\Device\\AtchKernel");
DECLARE_CONST_UNICODE_STRING(symbolicLinkName, L"\\DosDevices\\AtchKernel");

// Prototype
extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;

extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;

    KdPrint(("AtchKernel: DriverEntry - Bắt đầu khởi tạo.\n"));

    // Khởi tạo WDF_DRIVER_CONFIG
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.EvtDriverUnload = EvtDriverUnload;

    // Tạo WDFDRIVER object
    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             WDF_NO_OBJECT_ATTRIBUTES,
                             &config,
                             &driver);

    if (!NT_SUCCESS(status)) {
        KdPrint(("AtchKernel: WdfDriverCreate thất bại - Lỗi 0x%X\n", status));
        return status;
    }

    // Khởi tạo Device
    PWDFDEVICE_INIT pDeviceInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R);
    if (pDeviceInit == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        KdPrint(("AtchKernel: WdfControlDeviceInitAllocate thất bại.\n"));
        return status;
    }

    WdfDeviceInitSetDeviceType(pDeviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetCharacteristics(pDeviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);

    // Thiết lập File Object callbacks
    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig,
                               EvtDeviceFileCreate,
                               EvtFileClose,
                               WDF_NO_EVENT_CALLBACK);
    WdfDeviceInitSetFileObjectConfig(pDeviceInit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);

    status = WdfDeviceInitAssignName(pDeviceInit, &ntDeviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(pDeviceInit);
        KdPrint(("AtchKernel: WdfDeviceInitAssignName thất bại - Lỗi 0x%X\n", status));
        return status;
    }

    // Tạo Control Device
    WDFDEVICE controlDevice;
    status = WdfDeviceCreate(&pDeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &controlDevice);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AtchKernel: WdfDeviceCreate thất bại - Lỗi 0x%X\n", status));
        WdfDeviceInitFree(pDeviceInit);
        return status;
    }

    // Tạo Symbolic Link
    status = WdfDeviceCreateSymbolicLink(controlDevice, &symbolicLinkName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AtchKernel: WdfDeviceCreateSymbolicLink thất bại - Lỗi 0x%X\n", status));
        return status;
    }

    // Khởi tạo hàng đợi xử lý IOCTL (Queue)
    status = InitializeIoctlQueue(controlDevice);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AtchKernel: InitializeIoctlQueue thất bại - Lỗi 0x%X\n", status));
        return status;
    }

    WdfControlFinishInitializing(controlDevice);

    // Đăng ký các Callback bảo vệ (Process, Registry, Ob)
    status = RegisterSecurityCallbacks(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AtchKernel: Cảnh báo - Khởi tạo một số callbacks bảo mật thất bại - Lỗi 0x%X\n", status));
    }

    // Khởi tạo các module chống gian lận mới
    status = InitLoadImageNotify(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AtchKernel: InitLoadImageNotify thất bại - Lỗi 0x%X\n", status));
    }

    status = InitThreadNotify();
    if (!NT_SUCCESS(status)) {
        KdPrint(("AtchKernel: InitThreadNotify thất bại - Lỗi 0x%X\n", status));
    }

    if (DetectHypervisor()) {
        KdPrint(("AtchKernel: Phát hiện môi trường Hypervisor!\n"));
    } else {
        KdPrint(("AtchKernel: Không phát hiện Hypervisor.\n"));
    }

    UNICODE_STRING hwid;
    status = GenerateHWID(&hwid);
    if (NT_SUCCESS(status)) {
        KdPrint(("AtchKernel: HWID sinh ra: %wZ\n", &hwid));
        ExFreePoolWithTag(hwid.Buffer, 'diWH');
    } else {
        KdPrint(("AtchKernel: Sinh HWID thất bại - Lỗi 0x%X\n", status));
    }

    KdPrint(("AtchKernel: Driver khởi tạo thành công!\n"));
    return STATUS_SUCCESS;
}

extern "C" void EvtDriverUnload(_In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    KdPrint(("AtchKernel: EvtDriverUnload - Hủy đăng ký callbacks.\n"));
    
    UnloadThreadNotify();
    UnloadImageNotify();
    UnregisterSecurityCallbacks();
}
