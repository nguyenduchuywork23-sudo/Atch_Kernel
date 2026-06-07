#pragma once
#include <ntddk.h>
#include <wdf.h>

extern "C" {
    NTSTATUS InitializeIoctlQueue(WDFDEVICE Device);
    
    // File object callbacks
    EVT_WDF_DEVICE_FILE_CREATE EvtDeviceFileCreate;
    EVT_WDF_FILE_CLOSE EvtFileClose;

    // IOCTL callback
    EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;
    
    // API cho Inverted Call (gọi từ module Callbacks)
    void NotifyViolationToRing3(ULONG ProcessId, PCUNICODE_STRING ImagePath, ULONG ViolationType);

    ULONG GetExamClientProcessId();

    void LockExam();
    void UnlockExam();
    BOOLEAN IsExamLocked();
}
