#pragma once
#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif
    NTSTATUS RegisterSecurityCallbacks(PDRIVER_OBJECT DriverObject);
    void UnregisterSecurityCallbacks(VOID);

    // Undocumented NT APIs
    NTSTATUS NTAPI ZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    NTSTATUS NTAPI ZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
    NTSTATUS NTAPI ZwOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    NTSTATUS NTAPI ZwTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);

    void ForceKillProcess(HANDLE ProcessId);

    void SetDeviceObjectForCallbacks(PDEVICE_OBJECT DeviceObject);

    void InitCallbacks(VOID);
    void DrainWorkItems(VOID);

    // OMEGA-XVII: Export to header — previously used via inline extern in IoctlHandler.cpp
    PDEVICE_OBJECT GetDeviceObjectForCallbacks(VOID);
#ifdef __cplusplus
}
#endif
