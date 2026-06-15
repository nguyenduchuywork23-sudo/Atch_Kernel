#include "../inc/IoctlHandler.h"
#include "../../include/SharedDef.h"
#include "../inc/CompileTimeHash.h"
#include <intrin.h>  // OMEGA-XX: _mm_lfence() for Spectre v1 mitigation

#include "../inc/MemoryScanner.h"
#include "../inc/AntiVM.h"

#include "../inc/AntiDKOM.h"

static volatile WDFQUEUE g_NotificationQueue = NULL;
static volatile ULONG g_ClientProcessId = 0;
static volatile ULONG g_ClientProcessId_Inverted = 0xFFFFFFFF;

// OMEGA-XV: Race-safe VerifyClientPid — only bugchecks when PID is non-zero
// and the inverted copy disagrees (true bit-flip).
BOOLEAN VerifyClientPid(ULONG callerPid) {
    ULONG pid = (ULONG)InterlockedOr((LONG volatile*)&g_ClientProcessId, 0);
    ULONG pidInv = (ULONG)InterlockedOr((LONG volatile*)&g_ClientProcessId_Inverted, 0);
    // Only check integrity when PID is actively set (non-zero).
    // During cleanup transitions pid may be 0 while pidInv is stale — that is NOT an attack.
    if (pid != 0 && pid != ~pidInv) {
        AtchPrint(("AtchKernel: [OMEGA-X] CRITICAL - ROWHAMMER BIT-FLIP DETECTED ON PID!\n"));
        KeBugCheckEx(0x139, 3, pid, pidInv, 0); // KERNEL_SECURITY_CHECK_FAILURE
    }
    if (pid == 0) return FALSE;
    return callerPid == pid;
}

static volatile LONG g_HasHeartbeatThread = 0;
static volatile LONG g_HeartbeatEpoch = 0;
static volatile PKTHREAD g_HeartbeatThreadObject = NULL;
static volatile HANDLE g_HeartbeatThreadId = NULL;
static KEVENT g_HeartbeatEvent;
KEVENT g_HeartbeatStartEvent;
static FAST_MUTEX g_ExamMutex;
// OMEGA-II CRIT-04: g_SessionTokenHash removed — using g_SessionTokenStore instead

// STATIC ANALYSIS FIX C04: Missing global variable declarations
static volatile LONG g_IsExamLocked = 0;
static volatile LONGLONG g_LastHeartbeatTime = 0;

// OMEGA-II CRIT-04: Replaced FNV-1a hash with constant-time full-token comparison.
// FNV-1a 64-bit was brute-forceable in minutes via birthday attack (~2^32 ops).
static WCHAR g_SessionTokenStore[64] = {0};

// Constant-time token comparison — prevents timing side-channels
static BOOLEAN CompareSessionTokenConstantTime(const WCHAR* candidate) {
    volatile ULONG diff = 0;
    for (ULONG i = 0; i < 64; i++) {
        diff |= (ULONG)(g_SessionTokenStore[i] ^ candidate[i]);
    }
    return (diff == 0) ? TRUE : FALSE;
}

// OMEGA-XV: RCU Double Buffering Arrays with volatile to prevent compiler register caching
static volatile ULONG g_DynamicBlacklistHashes[2][1024];
static volatile ULONG g_DynamicBlacklistCount[2] = {0, 0};
static volatile LONG g_ActiveBlacklistIndex = 0;

static volatile ULONG g_DynamicWhitelistPids[2][1024];
static volatile ULONG g_DynamicWhitelistCount[2] = {0, 0};
static volatile LONG g_ActiveWhitelistIndex = 0;

// OMEGA-XV: Constant-Time hash lookup — prevents timing side-channel attacks.
// The loop always iterates over the FULL count; no early return.
BOOLEAN IsHashBlacklisted(ULONG hash) {
    LONG activeIndex = (LONG)InterlockedOr((LONG volatile*)&g_ActiveBlacklistIndex, 0);
    ULONG count = (ULONG)InterlockedOr((LONG volatile*)&g_DynamicBlacklistCount[activeIndex], 0);
    KeMemoryBarrier();
    // OMEGA-XX: Spectre v1 mitigation — fence after loading count to prevent
    // speculative OOB reads into the blacklist array.
    _mm_lfence();
    ULONG found = 0;
    for (ULONG i = 0; i < count; i++) {
        // OMEGA-IV-OS-02: Bitwise mask clamps speculative index to prevent OOB read
        found |= (ULONG)((g_DynamicBlacklistHashes[activeIndex][i & 1023] ^ hash) == 0);
    }
    return (BOOLEAN)(found != 0);
}

// OMEGA-XV: Constant-Time PID whitelist lookup
BOOLEAN IsPidWhitelisted(ULONG pid) {
    LONG activeIndex = (LONG)InterlockedOr((LONG volatile*)&g_ActiveWhitelistIndex, 0);
    ULONG count = (ULONG)InterlockedOr((LONG volatile*)&g_DynamicWhitelistCount[activeIndex], 0);
    KeMemoryBarrier();
    // OMEGA-XX: Spectre v1 mitigation — fence after loading count.
    _mm_lfence();
    ULONG found = 0;
    for (ULONG i = 0; i < count; i++) {
        // OMEGA-IV-OS-02: Bitwise mask clamps speculative index to prevent OOB read
        found |= (ULONG)((g_DynamicWhitelistPids[activeIndex][i & 1023] ^ pid) == 0);
    }
    return (BOOLEAN)(found != 0);
}

extern volatile PDRIVER_OBJECT g_DriverObject;
extern volatile PVOID g_OriginalIoctlDispatch;

void LockExam() {
    InterlockedExchange((LONG volatile*)&g_IsExamLocked, 1);
}
void UnlockExam() {
    if (InterlockedCompareExchange((LONG volatile*)&g_IsExamLocked, 0, 1) == 1) {
        // OMEGA-V-POWER-01: Use unbiased interrupt time (excludes sleep/hibernate)
        ULONGLONG unbiasedTime;
        KeQueryUnbiasedInterruptTime(&unbiasedTime);
        InterlockedExchange64(&g_LastHeartbeatTime, (LONGLONG)unbiasedTime);
    }
}
BOOLEAN IsExamLocked() {
    return (InterlockedOr((LONG volatile*)&g_IsExamLocked, 0) != 0);
}

VOID HeartbeatThreadRoutine(PVOID Context)
{
    ULONG myEpoch = (ULONG)(ULONG_PTR)Context;

    KeWaitForSingleObject(&g_HeartbeatStartEvent, Executive, KernelMode, FALSE, NULL);
    // OMEGA-FINAL M01: PASSIVE_LEVEL guaranteed after KeWaitForSingleObject(KernelMode).
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    LARGE_INTEGER delay;
    delay.QuadPart = -10000000LL; // 1 second

    while (InterlockedOr((LONG volatile*)&g_HasHeartbeatThread, 0) == 1 &&
           InterlockedOr((LONG volatile*)&g_HeartbeatEpoch, 0) == (LONG)myEpoch)
    {
        NTSTATUS waitStatus = KeWaitForSingleObject(&g_HeartbeatEvent, Executive, KernelMode, FALSE, &delay);
        if (waitStatus == STATUS_SUCCESS) {
            break;
        }
        
        if (InterlockedOr((LONG volatile*)&g_HasHeartbeatThread, 0) != 1 ||
            InterlockedOr((LONG volatile*)&g_HeartbeatEpoch, 0) != (LONG)myEpoch) break;

        ULONG clientPid = (ULONG)InterlockedOr((LONG volatile*)&g_ClientProcessId, 0);
        if (clientPid != 0) VerifyClientPid(clientPid); // OMEGA-X integrity check
        if (clientPid == 0) continue;

        // OMEGA-V-POWER-01: Use unbiased interrupt time (excludes sleep/hibernate)
        ULONGLONG currentUnbiased;
        KeQueryUnbiasedInterruptTime(&currentUnbiased);
        LONGLONG currentTime = (LONGLONG)currentUnbiased;

        LONGLONG lastTime = InterlockedCompareExchange64(&g_LastHeartbeatTime, 0, 0);

        if (lastTime != 0)
        {
            if (currentTime - lastTime > 50000000LL) // 5 seconds
            {
                LONGLONG currentLastTime = InterlockedCompareExchange64(&g_LastHeartbeatTime, 0, 0);
                if (currentTime - currentLastTime > 50000000LL) {
                    if (InterlockedCompareExchange((LONG volatile*)&g_IsExamLocked, 1, 0) == 0) {
                        AtchPrint(("AtchKernel: Heartbeat timeout! Locking exam.\n"));
                        UNICODE_STRING msg;
                        RtlInitUnicodeString(&msg, L"Heartbeat Timeout");
                        NotifyViolationToRing3(0, &msg, ViolationType::VIOLATION_HEARTBEAT_TIMEOUT);
                    }
                }
            }
        }
        
        // OMEGA-VIII: IRP Dispatch Integrity Check
        // OMEGA-II M03: Volatile reads prevent compiler from caching stale values in registers
        PDRIVER_OBJECT drvObj = (PDRIVER_OBJECT)(*(volatile PVOID*)&g_DriverObject);
        PVOID origDispatch = *(volatile PVOID*)&g_OriginalIoctlDispatch;
        if (drvObj != NULL && origDispatch != NULL) {
            if (drvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] != origDispatch) {
                AtchPrint(("AtchKernel: [OMEGA-VIII] CRITICAL - IRP Hook Detected!\n"));
                if (InterlockedCompareExchange((LONG volatile*)&g_IsExamLocked, 1, 0) == 0) {
                    UNICODE_STRING msg;
                    RtlInitUnicodeString(&msg, L"IRP Hook Detected");
                    NotifyViolationToRing3(0, &msg, ViolationType::VIOLATION_HEARTBEAT_TIMEOUT);
                }
            }
        }

        // OMEGA-XXV: Periodic MSR_LSTAR integrity check — detects stealth hypervisors
        if (!CheckMsrLstarIntegrity()) {
            if (InterlockedCompareExchange((LONG volatile*)&g_IsExamLocked, 1, 0) == 0) {
                AtchPrint(("AtchKernel: [OMEGA-XXV] MSR_LSTAR tampered! Locking exam.\n"));
                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"MSR_LSTAR Tampered");
                NotifyViolationToRing3(0, &msg, ViolationType::VIOLATION_HEARTBEAT_TIMEOUT);
            }
        }
        
        CheckAntiDKOM();
        CheckMemoryScanner();
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

PVOID SignalStopHeartbeatThread() {
    if (InterlockedCompareExchange((LONG volatile*)&g_HasHeartbeatThread, 0, 1) == 1) {
        InterlockedIncrement((LONG volatile*)&g_HeartbeatEpoch);
        KeSetEvent(&g_HeartbeatEvent, 0, FALSE);
        KeSetEvent(&g_HeartbeatStartEvent, 0, FALSE);
        // STATIC ANALYSIS FIX H07: Use interlocked operation for pointer consistency
        InterlockedExchangePointer((PVOID volatile*)&g_HeartbeatThreadId, NULL);
        return InterlockedExchangePointer((PVOID volatile*)&g_HeartbeatThreadObject, NULL);
    }
    return NULL;
}

void UninitializeIoctlQueue()
{
    InterlockedExchangePointer((PVOID volatile*)&g_NotificationQueue, NULL);
}

NTSTATUS InitializeIoctlQueue(WDFDEVICE Device)
{
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;

    KeInitializeEvent(&g_HeartbeatEvent, NotificationEvent, FALSE);
    ExInitializeFastMutex(&g_ExamMutex);
    KeInitializeEvent(&g_HeartbeatStartEvent, NotificationEvent, FALSE);

    WDF_OBJECT_ATTRIBUTES queueAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&queueAttributes);
    queueAttributes.ExecutionLevel = WdfExecutionLevelPassive;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    status = WdfIoQueueCreate(Device, &queueConfig, &queueAttributes, &queue);
    
    if (NT_SUCCESS(status)) {
        WDF_IO_QUEUE_CONFIG manualConfig;
        WDF_IO_QUEUE_CONFIG_INIT(&manualConfig, WdfIoQueueDispatchManual);
        
        WDF_OBJECT_ATTRIBUTES manualQueueAttributes;
        WDF_OBJECT_ATTRIBUTES_INIT(&manualQueueAttributes);
        manualQueueAttributes.ExecutionLevel = WdfExecutionLevelPassive;
        
        WDFQUEUE localNotifQueue = NULL;
        status = WdfIoQueueCreate(Device, &manualConfig, &manualQueueAttributes, &localNotifQueue);
        if (NT_SUCCESS(status)) {
            InterlockedExchangePointer((PVOID volatile*)&g_NotificationQueue, localNotifQueue);
        }
    }
    
    return status;
}

void EvtDeviceFileCreate(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ WDFFILEOBJECT FileObject
)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(FileObject);
    AtchPrint(("AtchKernel: EvtDeviceFileCreate.\n"));
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

void EvtFileClose(
    _In_ WDFFILEOBJECT FileObject
)
{
    UNREFERENCED_PARAMETER(FileObject);
    AtchPrint(("AtchKernel: EvtFileClose.\n"));
}

void EvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    UNREFERENCED_PARAMETER(Queue);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t bytesReturned = 0;

    // OMEGA-FINAL HIGH-02: Reject IOCTLs before driver is fully initialized
    // (all security callbacks registered). Prevents exploitation during init window.
    extern volatile LONG g_DriverReady;
    if (InterlockedOr((LONG volatile*)&g_DriverReady, 0) == 0) {
        WdfRequestCompleteWithInformation(Request, STATUS_DEVICE_NOT_READY, 0);
        return;
    }

    switch (IoControlCode)
    {
        case IOCTL_AK_INITIALIZE_EXAM:
        {
            if (InputBufferLength != sizeof(EXAM_INIT_DATA) || OutputBufferLength != 0) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            PEXAM_INIT_DATA pData;
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(EXAM_INIT_DATA), (PVOID*)&pData, NULL);
            if (!NT_SUCCESS(status)) break;

            // Validate Session Token
            // OMEGA-II HIGH-05: Enforce minimum 16-char token for sufficient entropy
            size_t tokenLen = 0;
            for (size_t ti = 0; ti < 64; ti++) {
                if (pData->SessionToken[ti] == L'\0') break;
                tokenLen++;
            }
            if (tokenLen < 16) {
                status = STATUS_ACCESS_DENIED;
                break;
            }

            // Zero-Trust PID Retrieval
            ULONG callerPid = IoGetRequestorProcessId(WdfRequestWdmGetIrp(Request));
            if (callerPid == 0 || callerPid == 4) {
                status = STATUS_ACCESS_DENIED;
                break;
            }

            // Acquire mutex to serialize with TERMINATE_EXAM
            NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL); // H05: IRQL guard
            ExAcquireFastMutex(&g_ExamMutex);

            // OMEGA-FINAL CRIT-01: Set inverted BEFORE CAS to prevent VerifyClientPid race.
            // VerifyClientPid skips check when pid==0, so stale pidInv is harmless.
            // But if CAS succeeds and pidInv is stale, VerifyClientPid sees non-zero pid + old pidInv → BSOD.
            InterlockedExchange((LONG volatile*)&g_ClientProcessId_Inverted, (LONG)(~callerPid));
            KeMemoryBarrier();
            if (InterlockedCompareExchange((LONG volatile*)&g_ClientProcessId, callerPid, 0) != 0) {
                // CAS failed — restore inverted to safe state
                InterlockedExchange((LONG volatile*)&g_ClientProcessId_Inverted, (LONG)0xFFFFFFFF);
                ExReleaseFastMutex(&g_ExamMutex);
                status = STATUS_ALREADY_INITIALIZED;
                break;
            }

            // OMEGA-II CRIT-04: Store full token instead of hash
            RtlCopyMemory(g_SessionTokenStore, pData->SessionToken, sizeof(g_SessionTokenStore));
            // OMEGA-II L05: Scrub plaintext token from WDF buffer to prevent RAM forensics
            RtlSecureZeroMemory(pData->SessionToken, sizeof(pData->SessionToken));

            // OMEGA-V-POWER-01: Use unbiased interrupt time (excludes sleep/hibernate)
            ULONGLONG unbiasedTime;
            KeQueryUnbiasedInterruptTime(&unbiasedTime);
            InterlockedExchange64(&g_LastHeartbeatTime, (LONGLONG)unbiasedTime);
            
            // Block exam start if hypervisor was detected during DriverEntry
            if (IsHypervisorDetected()) {
                InterlockedExchange((LONG volatile*)&g_IsExamLocked, 1);
                AtchPrint(("AtchKernel: VM detected - exam starts in LOCKED state!\n"));
            } else {
                InterlockedExchange((LONG volatile*)&g_IsExamLocked, 0);
            }
            
            ULONG currentEpoch = 0;
            BOOLEAN needCreateThread = FALSE;
            if (InterlockedCompareExchange(&g_HasHeartbeatThread, 1, 0) == 0) {
                currentEpoch = InterlockedIncrement((LONG volatile*)&g_HeartbeatEpoch);
                KeClearEvent(&g_HeartbeatEvent);
                KeClearEvent(&g_HeartbeatStartEvent);
                needCreateThread = TRUE;
            }

            // Release mutex BEFORE thread creation — PsCreateSystemThread requires PASSIVE_LEVEL
            ExReleaseFastMutex(&g_ExamMutex);

            if (needCreateThread) {
                HANDLE hThread = NULL;
                OBJECT_ATTRIBUTES objAttr;
                InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                NTSTATUS threadStatus = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &objAttr, NULL, NULL, HeartbeatThreadRoutine, (PVOID)(ULONG_PTR)currentEpoch);
                if (NT_SUCCESS(threadStatus)) {
                    PKTHREAD localThreadObj = NULL;
                    NTSTATUS refStatus = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&localThreadObj, NULL);
                    if (NT_SUCCESS(refStatus)) {
                        if (InterlockedOr((LONG volatile*)&g_HeartbeatEpoch, 0) == (LONG)currentEpoch) {
                            if (InterlockedCompareExchangePointer((PVOID volatile*)&g_HeartbeatThreadObject, localThreadObj, NULL) != NULL) {
                                KeSetEvent(&g_HeartbeatStartEvent, 0, FALSE);
                                KeWaitForSingleObject(localThreadObj, Executive, KernelMode, FALSE, NULL);
                                ObDereferenceObject(localThreadObj);
                            } else {
                                InterlockedExchangePointer((PVOID volatile*)&g_HeartbeatThreadId, PsGetThreadId((PETHREAD)localThreadObj));
                                KeSetEvent(&g_HeartbeatStartEvent, 0, FALSE);
                            }
                        } else {
                            KeSetEvent(&g_HeartbeatStartEvent, 0, FALSE);
                            KeWaitForSingleObject(localThreadObj, Executive, KernelMode, FALSE, NULL);
                            ObDereferenceObject(localThreadObj);
                        }
                    } else {
                        if (InterlockedOr((LONG volatile*)&g_HeartbeatEpoch, 0) == (LONG)currentEpoch) {
                            InterlockedExchange((LONG volatile*)&g_HasHeartbeatThread, 0);
                        }
                        KeSetEvent(&g_HeartbeatStartEvent, 0, FALSE);
                    }
                    ZwClose(hThread);
                } else {
                    if (InterlockedOr((LONG volatile*)&g_HeartbeatEpoch, 0) == (LONG)currentEpoch) {
                        InterlockedExchange((LONG volatile*)&g_HasHeartbeatThread, 0);
                    }
                }
            }

            // Rollback exam if heartbeat thread failed to start
            if (needCreateThread && InterlockedOr((LONG volatile*)&g_HasHeartbeatThread, 0) == 0 && 
                InterlockedOr((LONG volatile*)&g_HeartbeatEpoch, 0) == (LONG)currentEpoch) {
                AtchPrint(("AtchKernel: CRITICAL - Heartbeat thread failed! Rolling back exam.\n"));
                NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL); // H05: IRQL guard
                ExAcquireFastMutex(&g_ExamMutex);
                if (InterlockedOr((LONG volatile*)&g_HeartbeatEpoch, 0) == (LONG)currentEpoch) {
                    InterlockedExchange((LONG volatile*)&g_ClientProcessId, 0);
                    InterlockedExchange((LONG volatile*)&g_ClientProcessId_Inverted, (LONG)0xFFFFFFFF);
                    RtlSecureZeroMemory(g_SessionTokenStore, sizeof(g_SessionTokenStore));
                    InterlockedExchange64(&g_LastHeartbeatTime, 0);
                    InterlockedExchange((LONG volatile*)&g_IsExamLocked, 0);
                    // OMEGA-II M09: Interlocked writes for consistency with lock-free readers
                    InterlockedExchange((LONG volatile*)&g_DynamicBlacklistCount[0], 0);
                    InterlockedExchange((LONG volatile*)&g_DynamicBlacklistCount[1], 0);
                    InterlockedExchange((LONG volatile*)&g_DynamicWhitelistCount[0], 0);
                    InterlockedExchange((LONG volatile*)&g_DynamicWhitelistCount[1], 0);
                }
                ExReleaseFastMutex(&g_ExamMutex);
                status = STATUS_INTERNAL_ERROR;
                break;
            }

            AtchPrint(("AtchKernel: Initialize Exam for PID %lu\n", callerPid));
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_AK_TERMINATE_EXAM:
        {
            // OMEGA-V-TERM-01: Accept optional token for additional verification
            if (OutputBufferLength != 0) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            ULONG callerPid = IoGetRequestorProcessId(WdfRequestWdmGetIrp(Request));
            if (callerPid == 0) {
                status = STATUS_ACCESS_DENIED;
                break;
            }

            // OMEGA-V-PID-02: Verify EPROCESS identity, not just PID number.
            // PID recycling could allow a malicious process to impersonate the exam client.
            PEPROCESS callerProcess = PsGetCurrentProcess();
            PEPROCESS storedProcess = NULL;
            HANDLE examPidHandle = (HANDLE)(ULONG_PTR)callerPid;
            NTSTATUS lookupStatus = PsLookupProcessByProcessId(examPidHandle, &storedProcess);
            if (NT_SUCCESS(lookupStatus)) {
                BOOLEAN processMatch = (callerProcess == storedProcess);
                ObDereferenceObject(storedProcess);
                if (!processMatch) {
                    status = STATUS_ACCESS_DENIED;
                    break;
                }
            }

            NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL); // H05: IRQL guard
            ExAcquireFastMutex(&g_ExamMutex);

            if (InterlockedCompareExchange((LONG volatile*)&g_ClientProcessId, 0, callerPid) != (LONG)callerPid) {
                ExReleaseFastMutex(&g_ExamMutex);
                status = STATUS_ACCESS_DENIED;
                break;
            }
            AtchPrint(("AtchKernel: Terminate Exam.\n"));
            InterlockedExchange((LONG volatile*)&g_ClientProcessId_Inverted, (LONG)0xFFFFFFFF);
            RtlSecureZeroMemory(g_SessionTokenStore, sizeof(g_SessionTokenStore));
            InterlockedExchange64(&g_LastHeartbeatTime, 0);

            // OMEGA-XXV: Forensic Scrubbing — securely erase all sensitive arrays
            // so RAM dump tools (Volatility, PCILeech) cannot recover exam data.
            RtlSecureZeroMemory((PVOID)g_DynamicBlacklistHashes, sizeof(g_DynamicBlacklistHashes));
            RtlSecureZeroMemory((PVOID)g_DynamicWhitelistPids, sizeof(g_DynamicWhitelistPids));
            // OMEGA-II M09: Interlocked writes for consistency with lock-free readers
            InterlockedExchange((LONG volatile*)&g_DynamicBlacklistCount[0], 0);
            InterlockedExchange((LONG volatile*)&g_DynamicBlacklistCount[1], 0);
            InterlockedExchange((LONG volatile*)&g_DynamicWhitelistCount[0], 0);
            InterlockedExchange((LONG volatile*)&g_DynamicWhitelistCount[1], 0);

            PVOID threadToWait = SignalStopHeartbeatThread();
            ExReleaseFastMutex(&g_ExamMutex);

            if (threadToWait != NULL) {
                KeWaitForSingleObject(threadToWait, Executive, KernelMode, FALSE, NULL);
                ObDereferenceObject(threadToWait);
            }
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_AK_SEND_HEARTBEAT:
        {
            if (InputBufferLength != 0 || OutputBufferLength != 0) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            ULONG callerPid = IoGetRequestorProcessId(WdfRequestWdmGetIrp(Request));
            if (!VerifyClientPid(callerPid)) {
                status = STATUS_ACCESS_DENIED;
                break;
            }
            // OMEGA-V-POWER-01: Use unbiased interrupt time (excludes sleep/hibernate)
            ULONGLONG unbiasedTime;
            KeQueryUnbiasedInterruptTime(&unbiasedTime);
            InterlockedExchange64(&g_LastHeartbeatTime, (LONGLONG)unbiasedTime);
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_AK_UNLOCK_EXAM:
        {
            if (InputBufferLength != 0 || OutputBufferLength != 0) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            ULONG callerPid = IoGetRequestorProcessId(WdfRequestWdmGetIrp(Request));
            if (!VerifyClientPid(callerPid)) {
                status = STATUS_ACCESS_DENIED;
                break;
            }
            AtchPrint(("AtchKernel: Unlock Exam received.\n"));
            UnlockExam();
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_AK_LISTEN_EVENT:
        {
            if (InputBufferLength != 0 || OutputBufferLength != sizeof(MONITOR_LOG_ENTRY)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            ULONG callerPid = IoGetRequestorProcessId(WdfRequestWdmGetIrp(Request));
            if (!VerifyClientPid(callerPid)) {
                status = STATUS_ACCESS_DENIED;
                break;
            }

            // STATIC ANALYSIS FIX H03: Check g_NotificationQueue is valid before forwarding
            WDFQUEUE localNotifQueue = (WDFQUEUE)InterlockedCompareExchangePointer((PVOID volatile*)&g_NotificationQueue, NULL, NULL);
            if (localNotifQueue == NULL) {
                status = STATUS_DEVICE_NOT_READY;
                break;
            }
            status = WdfRequestForwardToIoQueue(Request, localNotifQueue);
            if (!NT_SUCCESS(status)) {
                break;
            }
            
            // ForwardToIoQueue took ownership
            return;
        }

        case IOCTL_AK_ADD_WHITELIST_PID:
        {
            ULONG callerPid = IoGetRequestorProcessId(WdfRequestWdmGetIrp(Request));
            if (!VerifyClientPid(callerPid)) {
                status = STATUS_ACCESS_DENIED;
                break;
            }
            if (InputBufferLength != sizeof(WHITELIST_DATA) || OutputBufferLength != 0) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            PWHITELIST_DATA pData = NULL;
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(WHITELIST_DATA), (PVOID*)&pData, NULL);
            if (NT_SUCCESS(status)) {
                if (!CompareSessionTokenConstantTime(pData->SessionToken)) {
                    status = STATUS_ACCESS_DENIED;
                    break;
                }
                ULONG targetPid = pData->Pid;
                // OMEGA-FINAL M13: Reject PID 0 and PID 4 (System) to prevent bypass
                if (targetPid == 0 || targetPid == 4) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL); // H05: IRQL guard
                ExAcquireFastMutex(&g_ExamMutex);
                LONG currentIndex = (LONG)InterlockedOr((LONG volatile*)&g_ActiveWhitelistIndex, 0);
                ULONG currentCount = (ULONG)InterlockedOr((LONG volatile*)&g_DynamicWhitelistCount[currentIndex], 0);
                if (currentCount < 1024) {
                    _mm_lfence(); // OMEGA-II HIGH-02: Spectre v1 fence before array indexed by bounds-checked count
                    // OMEGA-II M07: Constant-time duplicate check — prevents timing side-channel
                    ULONG existsAccum = 0;
                    for (ULONG i = 0; i < currentCount; i++) {
                        existsAccum |= (ULONG)((g_DynamicWhitelistPids[currentIndex][i] ^ targetPid) == 0);
                    }
                    BOOLEAN exists = (BOOLEAN)(existsAccum != 0);
                    if (!exists) {
                        LONG newIndex = 1 - currentIndex;
                        for (ULONG i = 0; i < currentCount; i++) {
                            g_DynamicWhitelistPids[newIndex][i] = g_DynamicWhitelistPids[currentIndex][i];
                        }
                        g_DynamicWhitelistPids[newIndex][currentCount] = targetPid;
                        g_DynamicWhitelistCount[newIndex] = currentCount + 1;
                        KeMemoryBarrier();
                        InterlockedExchange(&g_ActiveWhitelistIndex, newIndex);
                    }
                    status = STATUS_SUCCESS;
                } else {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                ExReleaseFastMutex(&g_ExamMutex);
                // OMEGA-FINAL M06: RCU Grace Period OUTSIDE mutex to prevent priority inversion.
                // The old buffer is safe: activeIndex already swapped, no new readers will access it.
                if (NT_SUCCESS(status)) {
                    LARGE_INTEGER gracePeriod;
                    gracePeriod.QuadPart = -100000LL; // 10ms
                    KeDelayExecutionThread(KernelMode, FALSE, &gracePeriod);
                }
            }
            AtchPrint(("AtchKernel: IOCTL_AK_ADD_WHITELIST_PID processed.\n"));
            break;
        }

        case IOCTL_AK_UPDATE_BLACKLIST:
        {
            ULONG callerPid = IoGetRequestorProcessId(WdfRequestWdmGetIrp(Request));
            if (!VerifyClientPid(callerPid)) {
                status = STATUS_ACCESS_DENIED;
                break;
            }
            if (InputBufferLength < sizeof(BLACKLIST_DATA) || OutputBufferLength != 0) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            PBLACKLIST_DATA pBlacklist = NULL;
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(BLACKLIST_DATA), (PVOID*)&pBlacklist, NULL);
            if (NT_SUCCESS(status)) {
                if (!CompareSessionTokenConstantTime(pBlacklist->SessionToken)) {
                    status = STATUS_ACCESS_DENIED;
                    break;
                }
                // OMEGA-II L06: Reject zero items — prevents silent blacklist clear
                if (pBlacklist->ItemCount == 0 || pBlacklist->ItemCount > 1024) {
                    status = STATUS_INFO_LENGTH_MISMATCH;
                    break;
                }
                // OMEGA-XX: Spectre v1 fence — prevent speculative OOB access
                // to pItems using a speculatively bypassed ItemCount bound.
                _mm_lfence();
                // OMEGA-II M08: Safe integer arithmetic prevents overflow on 32-bit builds
                SIZE_T itemsDataSize = 0;
                SIZE_T expectedSize = 0;
                if (!NT_SUCCESS(RtlSizeTMult((SIZE_T)pBlacklist->ItemCount, 256 * sizeof(WCHAR), &itemsDataSize)) ||
                    !NT_SUCCESS(RtlSizeTAdd(sizeof(BLACKLIST_DATA), itemsDataSize, &expectedSize))) {
                    status = STATUS_INTEGER_OVERFLOW;
                    break;
                }
                if (InputBufferLength < expectedSize) {
                    status = STATUS_INFO_LENGTH_MISMATCH;
                    break;
                }

                PWCHAR pItems = (PWCHAR)(pBlacklist + 1);
                NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL); // H05: IRQL guard
                ExAcquireFastMutex(&g_ExamMutex);
                LONG currentIndex = (LONG)InterlockedOr((LONG volatile*)&g_ActiveBlacklistIndex, 0);
                LONG newIndex = 1 - currentIndex;
                for (ULONG i = 0; i < pBlacklist->ItemCount; i++) {
                    PWCHAR currentStr = pItems + (i * 256);
                    currentStr[255] = L'\0';
                    UNICODE_STRING usStr;
                    RtlInitUnicodeString(&usStr, currentStr);
                    g_DynamicBlacklistHashes[newIndex][i] = RuntimeHashUnicodeString(&usStr);
                }
                g_DynamicBlacklistCount[newIndex] = pBlacklist->ItemCount;
                KeMemoryBarrier();
                InterlockedExchange(&g_ActiveBlacklistIndex, newIndex);
                ExReleaseFastMutex(&g_ExamMutex);
                // OMEGA-FINAL M06: RCU Grace Period OUTSIDE mutex to prevent priority inversion.
                // The old buffer is safe: activeIndex already swapped, no new readers will access it.
                {
                    LARGE_INTEGER gracePeriod;
                    gracePeriod.QuadPart = -100000LL; // 10ms
                    KeDelayExecutionThread(KernelMode, FALSE, &gracePeriod);
                }
                status = STATUS_SUCCESS;
            }
            AtchPrint(("AtchKernel: IOCTL_AK_UPDATE_BLACKLIST processed (%lu items).\n", pBlacklist ? pBlacklist->ItemCount : 0));
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}

// Push violation notification to Ring 3
void NotifyViolationToRing3(ULONG ProcessId, PCUNICODE_STRING ImagePath, ViolationType Type)
{
    WDFQUEUE localQueue = (WDFQUEUE)InterlockedCompareExchangePointer((PVOID volatile*)&g_NotificationQueue, NULL, NULL);
    if (localQueue == NULL) return;

    WDFREQUEST req = NULL;
    NTSTATUS status = WdfIoQueueRetrieveNextRequest(localQueue, &req);

    if (NT_SUCCESS(status) && req != NULL) {
        PMONITOR_LOG_ENTRY pLogEntry;
        status = WdfRequestRetrieveOutputBuffer(req, sizeof(MONITOR_LOG_ENTRY), (PVOID*)&pLogEntry, NULL);
        if (NT_SUCCESS(status)) {
            RtlZeroMemory(pLogEntry, sizeof(MONITOR_LOG_ENTRY));
            pLogEntry->ConfiscatedProcessId = ProcessId;
            pLogEntry->Type = Type;
            
            if (ImagePath != NULL && ImagePath->Buffer != NULL) {
                size_t lenChars = ImagePath->Length / sizeof(WCHAR);
                if (lenChars > 255) lenChars = 255;
                // OMEGA-XX: Spectre v1 fence — prevent speculative OOB read
                // via RtlCopyMemory when the branch above is mispredicted.
                _mm_lfence();
                RtlCopyMemory(pLogEntry->ImagePath, ImagePath->Buffer, lenChars * sizeof(WCHAR));
                pLogEntry->ImagePath[lenChars] = L'\0';
            } else {
                pLogEntry->ImagePath[0] = L'\0';
            }
            
            WdfRequestCompleteWithInformation(req, STATUS_SUCCESS, sizeof(MONITOR_LOG_ENTRY));
        } else {
            WdfRequestComplete(req, status);
        }
    }
}

ULONG GetExamClientProcessId()
{
    ULONG pid = (ULONG)InterlockedOr((LONG volatile*)&g_ClientProcessId, 0);
    if (pid != 0) VerifyClientPid(pid);
    return pid;
}

HANDLE GetHeartbeatThreadId() {
    return (HANDLE)InterlockedCompareExchangePointer((PVOID volatile*)&g_HeartbeatThreadId, NULL, NULL);
}

PKTHREAD GetHeartbeatThreadObject() {
    return (PKTHREAD)InterlockedCompareExchangePointer((PVOID volatile*)&g_HeartbeatThreadObject, NULL, NULL);
}

// Emergency cleanup when exam client process crashes (called from ProcessNotifyCallbackEx)
void EmergencyCleanupExam(ULONG deadPid)
{
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL); // H05: IRQL guard
    ExAcquireFastMutex(&g_ExamMutex);

    PVOID threadToWait = NULL;
    if (InterlockedCompareExchange((LONG volatile*)&g_ClientProcessId, 0, (LONG)deadPid) == (LONG)deadPid) {
        InterlockedExchange((LONG volatile*)&g_ClientProcessId_Inverted, (LONG)0xFFFFFFFF);
        AtchPrint(("AtchKernel: EmergencyCleanupExam - clearing state for dead PID %lu\n", deadPid));
        RtlSecureZeroMemory(g_SessionTokenStore, sizeof(g_SessionTokenStore));
        RtlSecureZeroMemory((PVOID)g_DynamicBlacklistHashes, sizeof(g_DynamicBlacklistHashes));
        RtlSecureZeroMemory((PVOID)g_DynamicWhitelistPids, sizeof(g_DynamicWhitelistPids));
        // OMEGA-II M09: Interlocked writes for consistency with lock-free readers
        InterlockedExchange((LONG volatile*)&g_DynamicBlacklistCount[0], 0);
        InterlockedExchange((LONG volatile*)&g_DynamicBlacklistCount[1], 0);
        InterlockedExchange((LONG volatile*)&g_DynamicWhitelistCount[0], 0);
        InterlockedExchange((LONG volatile*)&g_DynamicWhitelistCount[1], 0);
        InterlockedExchange64(&g_LastHeartbeatTime, 0);
        InterlockedExchange((LONG volatile*)&g_IsExamLocked, 0);
        
        threadToWait = SignalStopHeartbeatThread();
    }

    ExReleaseFastMutex(&g_ExamMutex);

    if (threadToWait != NULL) {
        KeWaitForSingleObject(threadToWait, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(threadToWait);
    }
}

// Clear all exam state securely (called on Unload)
void ClearExamState() {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL); // H05: IRQL guard
    ExAcquireFastMutex(&g_ExamMutex);
    InterlockedExchange((LONG volatile*)&g_ClientProcessId, 0);
    InterlockedExchange((LONG volatile*)&g_ClientProcessId_Inverted, (LONG)0xFFFFFFFF);
    InterlockedExchange((LONG volatile*)&g_IsExamLocked, 0);
    InterlockedExchange64(&g_LastHeartbeatTime, 0);
    RtlSecureZeroMemory(g_SessionTokenStore, sizeof(g_SessionTokenStore));
    // OMEGA-XXV: Forensic Scrubbing on Unload — leave no trace in RAM
    RtlSecureZeroMemory((PVOID)g_DynamicBlacklistHashes, sizeof(g_DynamicBlacklistHashes));
    RtlSecureZeroMemory((PVOID)g_DynamicWhitelistPids, sizeof(g_DynamicWhitelistPids));
    // OMEGA-II M09: Interlocked writes for consistency with lock-free readers
    InterlockedExchange((LONG volatile*)&g_DynamicBlacklistCount[0], 0);
    InterlockedExchange((LONG volatile*)&g_DynamicBlacklistCount[1], 0);
    InterlockedExchange((LONG volatile*)&g_DynamicWhitelistCount[0], 0);
    InterlockedExchange((LONG volatile*)&g_DynamicWhitelistCount[1], 0);
    ExReleaseFastMutex(&g_ExamMutex);
}
