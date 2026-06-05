#pragma once
#include <ntddk.h>

extern "C" {
    NTSTATUS RegisterSecurityCallbacks(PDRIVER_OBJECT DriverObject);
    void UnregisterSecurityCallbacks();

    // Undocumented NT APIs
    NTSTATUS ZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    NTSTATUS ZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
    NTSTATUS ZwOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    NTSTATUS ZwTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);

    void ForceKillExamProcess(HANDLE ProcessId);
}
