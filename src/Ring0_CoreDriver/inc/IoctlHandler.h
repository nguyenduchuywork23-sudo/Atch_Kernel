#pragma once
#include <ntifs.h>
#include <wdf.h>
#include "../../include/SharedDef.h"

#ifdef __cplusplus
extern "C" {
#endif
    NTSTATUS InitializeIoctlQueue(WDFDEVICE Device);
    void UninitializeIoctlQueue(VOID);
    
    // File object callbacks
    EVT_WDF_DEVICE_FILE_CREATE EvtDeviceFileCreate;
    EVT_WDF_FILE_CLOSE EvtFileClose;

    // IOCTL callback
    EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;
    
    // API cho Inverted Call (gọi từ module Callbacks)
    void NotifyViolationToRing3(ULONG ProcessId, PCUNICODE_STRING ImagePath, ViolationType Type);

    ULONG GetExamClientProcessId(VOID);

    void LockExam(VOID);
    void UnlockExam(VOID);
    BOOLEAN IsExamLocked(VOID);

    BOOLEAN IsHashBlacklisted(ULONG hash);
    BOOLEAN IsPidWhitelisted(ULONG pid);

    PVOID SignalStopHeartbeatThread(VOID);

    HANDLE GetHeartbeatThreadId(VOID);
    PKTHREAD GetHeartbeatThreadObject(VOID);

    // Emergency cleanup when exam client crashes without calling TERMINATE_EXAM
    void EmergencyCleanupExam(ULONG deadPid);

    // Clear all exam state securely (called on Unload to prevent link errors)
    void ClearExamState(VOID);

    // OMEGA-XVII: Export to header — previously used via inline extern in Callbacks.cpp
    PEPROCESS GetClientEProcess(VOID);
#ifdef __cplusplus
}
#endif
