#include <ntifs.h>
#include <wdf.h>
#include <wdmsec.h>
#include "../../include/SharedDef.h"
#include "../inc/IoctlHandler.h"
#include "../inc/Callbacks.h"
#include "../inc/AntiBYOVD.h"
#include "../inc/AntiVM.h"
#include "../inc/HWID.h"
#include "../inc/LoadImageNotify.h"
#include "../inc/ThreadNotify.h"
#include "../inc/InputBlocker.h"
#include "../inc/MemoryScanner.h"
#include "../inc/HypervisorCore.h"
#include "../inc/DmaProtection.h"

// Biến toàn cục để lưu IRP Dispatch của WDF chống SSDT/IRP Hooking
// OMEGA-II M03: volatile prevents compiler caching stale values in heartbeat thread loop
volatile PVOID g_OriginalIoctlDispatch = NULL;
volatile PDRIVER_OBJECT g_DriverObject = NULL;

// OMEGA-FINAL HIGH-02: Driver readiness gate — prevents IOCTLs before all callbacks are registered
volatile LONG g_DriverReady = 0;

// Khai báo tên thiết bị và DOS device name
DECLARE_CONST_UNICODE_STRING(ntDeviceName, L"\\Device\\AtchKernel");
DECLARE_CONST_UNICODE_STRING(symbolicLinkName, L"\\DosDevices\\AtchKernel");

// Global control device
WDFDEVICE g_ControlDevice = NULL;

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

    AtchPrint(("AtchKernel: DriverEntry - Bắt đầu khởi tạo.\n"));

    // Khởi tạo WDF_DRIVER_CONFIG
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    // [OMEGA-X DELTA] CHỐNG SC STOP: Không đăng ký EvtDriverUnload,
    // biến AtchKernel thành driver "bất tử" trong phiên làm việc.
    // config.EvtDriverUnload = EvtDriverUnload;

    // Tạo WDFDRIVER object
    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             WDF_NO_OBJECT_ATTRIBUTES,
                             &config,
                             &driver);

    if (!NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: WdfDriverCreate thất bại - Lỗi 0x%X\n", status));
        return status;
    }

    // OMEGA-V-WDF-01: Restrict to System+Admin only — blocks unprivileged IOCTL probing
    PWDFDEVICE_INIT pDeviceInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (pDeviceInit == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        AtchPrint(("AtchKernel: WdfControlDeviceInitAllocate thất bại.\n"));
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
        AtchPrint(("AtchKernel: WdfDeviceInitAssignName thất bại - Lỗi 0x%X\n", status));
        return status;
    }

    // Tạo Control Device
    WDFDEVICE controlDevice = NULL;
    status = WdfDeviceCreate(&pDeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &controlDevice);
    // WdfDeviceCreate frees pDeviceInit on both success and failure.
    // Set to NULL to prevent double-free or use-after-free.
    pDeviceInit = NULL;
    if (!NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: WdfDeviceCreate thất bại - Lỗi 0x%X\n", status));
        return status;
    }

    // Tạo Symbolic Link
    status = WdfDeviceCreateSymbolicLink(controlDevice, &symbolicLinkName);
    if (!NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: WdfDeviceCreateSymbolicLink thất bại - Lỗi 0x%X\n", status));
        goto cleanup;
    }

    status = InitializeIoctlQueue(controlDevice);
    if (!NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: InitializeIoctlQueue thất bại - Lỗi 0x%X\n", status));
        goto cleanup;
    }

    g_ControlDevice = controlDevice;
    SetDeviceObjectForCallbacks(WdfDeviceWdmGetDeviceObject(controlDevice));

    // OMEGA-IX: Save original IRP Dispatch BEFORE finishing initialization to prevent TOCTOU race
    g_DriverObject = DriverObject;
    g_OriginalIoctlDispatch = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];

    // OMEGA-FINAL HIGH-02: WdfControlFinishInitializing moved after all callbacks register (see below)

    // Khởi tạo Input Blocker (filter devices cho keyboard/mouse)
    status = InitializeInputBlocker();
    if (!NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: InitializeInputBlocker thất bại - Lỗi 0x%X\n", status));
        goto cleanup;
    }

    // Khởi tạo các sự kiện callbacks
    InitCallbacks();

    // Đăng ký các Callback bảo vệ (Process, Registry, Ob)
    status = RegisterSecurityCallbacks(DriverObject);
    if (!NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: Cảnh báo - Khởi tạo một số callbacks bảo mật thất bại - Lỗi 0x%X\n", status));
        goto cleanup;
    }

    // Khởi tạo các module chống gian lận mới
    status = InitLoadImageNotify(DriverObject);
    if (!NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: InitLoadImageNotify thất bại - Lỗi 0x%X\n", status));
        goto cleanup;
    }

    status = InitThreadNotify();
    if (!NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: InitThreadNotify thất bại - Lỗi 0x%X\n", status));
        goto cleanup;
    }

    status = InitDmaProtection(DriverObject);
    if (!NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: InitDmaProtection thất bại - Lỗi 0x%X\n", status));
        goto cleanup;
    }

    // OMEGA-FINAL HIGH-02: Finish device initialization AFTER all callbacks are registered
    WdfControlFinishInitializing(controlDevice);
    InterlockedExchange(&g_DriverReady, 1);

    if (DetectHypervisor()) {
        AtchPrint(("AtchKernel: Phát hiện môi trường Hypervisor!\n"));
    } else {
        AtchPrint(("AtchKernel: Không phát hiện Hypervisor.\n"));
    }

    UNICODE_STRING hwid;
    status = GenerateHWID(&hwid);
    if (NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: HWID sinh ra: %wZ\n", &hwid));
        if (hwid.Buffer) {
            RtlSecureZeroMemory(hwid.Buffer, hwid.MaximumLength);
            ExFreePoolWithTag(hwid.Buffer, 'diWH');
        }
    } else {
        AtchPrint(("AtchKernel: Sinh HWID thất bại - Lỗi 0x%X\n", status));
    }

    AtchPrint(("AtchKernel: Driver khởi tạo thành công!\n"));
    
    // Khởi tạo lõi Hypervisor Ring -1
    InitHypervisorCore();

    // OMEGA-V-BOOT-04: Self-register for Safe Mode to prevent Safe Mode bypass attack.
    // Without this, attacker boots to Safe Mode → disables driver → reboots → zero protection.
    {
        UNICODE_STRING safeBootMinimal;
        RtlInitUnicodeString(&safeBootMinimal,
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\AtchKernel.sys");
        UNICODE_STRING safeBootNetwork;
        RtlInitUnicodeString(&safeBootNetwork,
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\AtchKernel.sys");

        HANDLE keyHandle = NULL;
        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &safeBootMinimal, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        ULONG disposition = 0;
        NTSTATUS sbStatus = ZwCreateKey(&keyHandle, KEY_SET_VALUE, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);
        if (NT_SUCCESS(sbStatus) && keyHandle) {
            UNICODE_STRING valueName;
            RtlInitUnicodeString(&valueName, L"");
            UNICODE_STRING valueData;
            RtlInitUnicodeString(&valueData, L"Driver");
            // OMEGA-XVII: Check return to detect SafeBoot registration failure
            NTSTATUS svkStatus = ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, valueData.Buffer, valueData.Length + sizeof(WCHAR));
            if (!NT_SUCCESS(svkStatus)) {
                AtchPrint(("AtchKernel: [OMEGA-XVII] WARNING - SafeBoot Minimal registration failed: 0x%X\n", svkStatus));
            }
            ZwClose(keyHandle);
        }

        keyHandle = NULL;
        InitializeObjectAttributes(&objAttr, &safeBootNetwork, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        sbStatus = ZwCreateKey(&keyHandle, KEY_SET_VALUE, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);
        if (NT_SUCCESS(sbStatus) && keyHandle) {
            UNICODE_STRING valueName;
            RtlInitUnicodeString(&valueName, L"");
            UNICODE_STRING valueData;
            RtlInitUnicodeString(&valueData, L"Driver");
            // OMEGA-XVII: Check return to detect SafeBoot registration failure
            NTSTATUS svk2 = ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, valueData.Buffer, valueData.Length + sizeof(WCHAR));
            if (!NT_SUCCESS(svk2)) {
                AtchPrint(("AtchKernel: [OMEGA-XVII] WARNING - SafeBoot Network registration failed: 0x%X\n", svk2));
            }
            ZwClose(keyHandle);
        }
        AtchPrint(("AtchKernel: SafeBoot self-registration complete.\n"));
    }

    // OMEGA-VI-BOOT-01: Harden ACL on service registry key.
    // Prevents pre-boot ImagePath tampering: attacker modifies ImagePath before driver
    // loads → driver loads malicious binary instead. Lock key to SYSTEM-only.
    {
        UNICODE_STRING serviceKeyPath;
        RtlInitUnicodeString(&serviceKeyPath, RegistryPath->Buffer);
        HANDLE svcKeyHandle = NULL;
        OBJECT_ATTRIBUTES svcObjAttr;
        InitializeObjectAttributes(&svcObjAttr, &serviceKeyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        NTSTATUS aclStatus = ZwOpenKey(&svcKeyHandle, WRITE_DAC | READ_CONTROL, &svcObjAttr);
        if (NT_SUCCESS(aclStatus) && svcKeyHandle) {
            // SDDL: SYSTEM full control only, deny all others write
            UNICODE_STRING sddlString;
            RtlInitUnicodeString(&sddlString, L"D:P(A;;KA;;;SY)");
            // Use SeConvertStringSecurityDescriptor if available, or build manually
            // Simple approach: use ZwSetSecurityObject with a DACL that allows only SYSTEM
            SECURITY_DESCRIPTOR sd;
            NTSTATUS sdStatus = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
            if (NT_SUCCESS(sdStatus)) {
                // Create ACL with single ACE: SYSTEM full control
                UCHAR aclBuffer[128] = {0};
                PACL pAcl = (PACL)aclBuffer;
                sdStatus = RtlCreateAcl(pAcl, sizeof(aclBuffer), ACL_REVISION);
                if (NT_SUCCESS(sdStatus)) {
                    // SID for SYSTEM (S-1-5-18)
                    SID systemSid = {0};
                    systemSid.Revision = SID_REVISION;
                    systemSid.SubAuthorityCount = 1;
                    systemSid.IdentifierAuthority = SECURITY_NT_AUTHORITY;
                    systemSid.SubAuthority[0] = SECURITY_LOCAL_SYSTEM_RID;

                    sdStatus = RtlAddAccessAllowedAce(pAcl, ACL_REVISION, KEY_ALL_ACCESS, &systemSid);
                    if (NT_SUCCESS(sdStatus)) {
                        sdStatus = RtlSetDaclSecurityDescriptor(&sd, TRUE, pAcl, FALSE);
                        if (NT_SUCCESS(sdStatus)) {
                            // OMEGA-XVII: Check return — ACL hardening failure is security-critical
                            NTSTATUS secStatus = ZwSetSecurityObject(svcKeyHandle, DACL_SECURITY_INFORMATION, &sd);
                            if (NT_SUCCESS(secStatus)) {
                                AtchPrint(("AtchKernel: Service key ACL hardened to SYSTEM-only.\n"));
                            } else {
                                AtchPrint(("AtchKernel: [OMEGA-XVII] WARNING - ACL hardening FAILED: 0x%X. Service key may be tamper-vulnerable!\n", secStatus));
                            }
                        }
                    }
                }
            }
            ZwClose(svcKeyHandle);
        }
    }

    return STATUS_SUCCESS;

cleanup:
    UninitializeInputBlocker();
    UnloadThreadNotify();
    UnloadImageNotify();
    UnregisterSecurityCallbacks();
    DrainWorkItems();
    if (controlDevice) {
        WdfObjectDelete(controlDevice);
        g_ControlDevice = NULL;
    }
    return status;
}

extern "C" void EvtDriverUnload(_In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    // OMEGA-IX-R2-001: Reject all new IOCTLs immediately — closes the window
    // between unload start and WDF queue destruction.
    extern volatile LONG g_DriverReady;
    InterlockedExchange(&g_DriverReady, 0);

    // OMEGA-II CRIT-03: Prevent new work items FIRST — before any callback unregistration.
    // Without this, in-flight callbacks can queue work items referencing a device about to be deleted.
    SetDeviceObjectForCallbacks(NULL);

    AtchPrint(("AtchKernel: EvtDriverUnload - Hủy đăng ký callbacks.\n"));

    // Phase 2: Clear exam state FIRST — prevents ObCallback zombie PID log-spam
    // OMEGA-VII-R1-003: Moved before heartbeat wait to close the window where
    // stale PID triggers infinite ScheduleEmergencyCleanup attempts.
    extern void ClearExamState();
    ClearExamState();

    // Phase 2b: Stop heartbeat monitoring thread
    PVOID threadToWait = SignalStopHeartbeatThread();
    if (threadToWait != NULL) {
        KeWaitForSingleObject(threadToWait, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(threadToWait);
    }

    // Phase 3: Tear down filter devices (waits for in-flight IRPs)
    UninitializeInputBlocker();

    // Phase 4: Unregister all notification callbacks
    UnloadThreadNotify();
    UnloadImageNotify();
    UnregisterSecurityCallbacks();
    
    // Phase 5: Wait for all outstanding work items
    DrainWorkItems();
    

    UninitializeIoctlQueue();

    // Phase 6: Uninit DMA Protection
    UninitDmaProtection();

    // Phase 7: Free Hypervisor VMXON region (STATIC ANALYSIS FIX C02)
    UninitHypervisorCore();

    // Phase 8: Delete device and all child WDF objects
    if (g_ControlDevice) {
        WdfObjectDelete(g_ControlDevice);
        g_ControlDevice = NULL;
    }
}
