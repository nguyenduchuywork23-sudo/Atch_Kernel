#include "../inc/IoctlHandler.h"
#include "../../include/SharedDef.h"

// Biến lưu trữ Request của Inverted Call
static WDFREQUEST g_PendingListenRequest = NULL;
static KSPIN_LOCK g_ListenRequestLock;
static volatile ULONG g_ClientProcessId = 0;

static volatile LONG g_IsExamLocked = 0;
static LARGE_INTEGER g_LastHeartbeatTime = {0};
static volatile LONG g_HeartbeatThreadRunning = 0;
static PKTHREAD g_HeartbeatThreadObject = NULL;
static KEVENT g_HeartbeatEvent;

void LockExam() {
    InterlockedExchange(&g_IsExamLocked, 1);
}
void UnlockExam() {
    InterlockedExchange(&g_IsExamLocked, 0);
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    LONGLONG expected, newTime;
    do {
        expected = g_LastHeartbeatTime.QuadPart;
        newTime = currentTime.QuadPart;
    } while (InterlockedCompareExchange64(&g_LastHeartbeatTime.QuadPart, newTime, expected) != expected);
}
BOOLEAN IsExamLocked() {
    return (InterlockedOr((LONG volatile*)&g_IsExamLocked, 0) != 0);
}

VOID HeartbeatThreadRoutine(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    LARGE_INTEGER delay;
    delay.QuadPart = -10000000LL; // 1 second

    while (InterlockedOr((LONG volatile*)&g_HeartbeatThreadRunning, 0) != 0)
    {
        NTSTATUS waitStatus = KeWaitForSingleObject(&g_HeartbeatEvent, Executive, KernelMode, FALSE, &delay);
        if (waitStatus == STATUS_SUCCESS) {
            break;
        }
        
        if (InterlockedOr((LONG volatile*)&g_HeartbeatThreadRunning, 0) == 0) break;

        ULONG clientPid = (ULONG)InterlockedOr((LONG volatile*)&g_ClientProcessId, 0);
        if (clientPid == 0) continue;

        LARGE_INTEGER currentTime;
        KeQuerySystemTime(&currentTime);

        LONGLONG lastTime = InterlockedCompareExchange64(&g_LastHeartbeatTime.QuadPart, 0, 0);

        if (lastTime != 0)
        {
            // If > 5 seconds (50,000,000 100-nanoseconds)
            if (currentTime.QuadPart - lastTime > 50000000LL)
            {
                if (InterlockedOr((LONG volatile*)&g_IsExamLocked, 0) == 0) {
                    KdPrint(("AtchKernel: Heartbeat timeout! Locking exam.\n"));
                    LockExam();
                    UNICODE_STRING msg;
                    RtlInitUnicodeString(&msg, L"Heartbeat Timeout");
                    NotifyViolationToRing3(0, &msg, VIOLATION_HEARTBEAT_TIMEOUT);
                }
            }
        }
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

void StopHeartbeatThread() {
    InterlockedExchange((LONG volatile*)&g_HeartbeatThreadRunning, 0);
    KeSetEvent(&g_HeartbeatEvent, 0, FALSE);
    PVOID threadObj = InterlockedExchangePointer((PVOID volatile*)&g_HeartbeatThreadObject, NULL);
    if (threadObj != NULL) {
        KeWaitForSingleObject(threadObj, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(threadObj);
    }
}

NTSTATUS InitializeIoctlQueue(WDFDEVICE Device)
{
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;

    KeInitializeSpinLock(&g_ListenRequestLock);
    KeInitializeEvent(&g_HeartbeatEvent, NotificationEvent, FALSE);

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    status = WdfIoQueueCreate(Device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    
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
    KdPrint(("AtchKernel: EvtDeviceFileCreate.\n"));
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

void EvtFileClose(
    _In_ WDFFILEOBJECT FileObject
)
{
    UNREFERENCED_PARAMETER(FileObject);
    KdPrint(("AtchKernel: EvtFileClose.\n"));
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ListenRequestLock, &oldIrql);
    WDFREQUEST req = g_PendingListenRequest;
    g_PendingListenRequest = NULL;
    KeReleaseSpinLock(&g_ListenRequestLock, oldIrql);

    if (req != NULL) {
        NTSTATUS unmarkStatus = WdfRequestUnmarkCancelable(req);
        if (NT_SUCCESS(unmarkStatus)) {
            WdfRequestComplete(req, STATUS_CANCELLED);
        }
    }
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

    switch (IoControlCode)
    {
        case IOCTL_AK_INITIALIZE_EXAM:
        {
            if (InputBufferLength < sizeof(EXAM_INIT_DATA)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PEXAM_INIT_DATA pData;
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(EXAM_INIT_DATA), (PVOID*)&pData, NULL);
            if (NT_SUCCESS(status)) {
                InterlockedExchange((LONG volatile*)&g_ClientProcessId, pData->ClientProcessId);
                LARGE_INTEGER currentTime;
                KeQuerySystemTime(&currentTime);
                LONGLONG expected, newTime;
                do {
                    expected = g_LastHeartbeatTime.QuadPart;
                    newTime = currentTime.QuadPart;
                } while (InterlockedCompareExchange64(&g_LastHeartbeatTime.QuadPart, newTime, expected) != expected);
                
                InterlockedExchange((LONG volatile*)&g_IsExamLocked, 0);
                
                if (InterlockedCompareExchange(&g_HeartbeatThreadRunning, 1, 0) == 0) {
                    KeClearEvent(&g_HeartbeatEvent);
                    HANDLE hThread = NULL;
                    OBJECT_ATTRIBUTES objAttr;
                    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                    NTSTATUS threadStatus = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &objAttr, NULL, NULL, HeartbeatThreadRoutine, NULL);
                    if (NT_SUCCESS(threadStatus)) {
                        PKTHREAD localThreadObj = NULL;
                        ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&localThreadObj, NULL);
                        InterlockedExchangePointer((PVOID volatile*)&g_HeartbeatThreadObject, localThreadObj);
                        ZwClose(hThread);
                    } else {
                        InterlockedExchange(&g_HeartbeatThreadRunning, 0);
                    }
                }
                KdPrint(("AtchKernel: Initialize Exam for PID %lu\n", pData->ClientProcessId));
            }
            break;
        }

        case IOCTL_AK_TERMINATE_EXAM:
        {
            KdPrint(("AtchKernel: Terminate Exam.\n"));
            InterlockedExchange((LONG volatile*)&g_ClientProcessId, 0);
            StopHeartbeatThread();
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_AK_SEND_HEARTBEAT:
        {
            LARGE_INTEGER currentTime;
            KeQuerySystemTime(&currentTime);
            LONGLONG expected, newTime;
            do {
                expected = g_LastHeartbeatTime.QuadPart;
                newTime = currentTime.QuadPart;
            } while (InterlockedCompareExchange64(&g_LastHeartbeatTime.QuadPart, newTime, expected) != expected);
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_AK_UNLOCK_EXAM:
        {
            KdPrint(("AtchKernel: Unlock Exam received.\n"));
            UnlockExam();
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_AK_LISTEN_EVENT:
        {
            if (OutputBufferLength < sizeof(MONITOR_LOG_ENTRY)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            // Đưa request vào trạng thái chờ (Inverted Call)
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_ListenRequestLock, &oldIrql);
            WDFREQUEST oldReq = g_PendingListenRequest;
            g_PendingListenRequest = NULL;
            KeReleaseSpinLock(&g_ListenRequestLock, oldIrql);
            
            if (oldReq != NULL) {
                NTSTATUS unmarkStatus = WdfRequestUnmarkCancelable(oldReq);
                if (NT_SUCCESS(unmarkStatus)) {
                    WdfRequestComplete(oldReq, STATUS_CANCELLED);
                }
            }
            
            // Đánh dấu Request mới là cancelable TRƯỚC KHI lưu vào biến toàn cục
            NTSTATUS markStatus = WdfRequestMarkCancelableEx(Request, [](WDFREQUEST Req) {
                KIRQL irql;
                KeAcquireSpinLock(&g_ListenRequestLock, &irql);
                if (g_PendingListenRequest == Req) {
                    g_PendingListenRequest = NULL;
                }
                KeReleaseSpinLock(&g_ListenRequestLock, irql);
                WdfRequestComplete(Req, STATUS_CANCELLED);
            });

            if (!NT_SUCCESS(markStatus)) {
                status = markStatus;
                break;
            }
            
            KeAcquireSpinLock(&g_ListenRequestLock, &oldIrql);
            g_PendingListenRequest = Request;
            KeReleaseSpinLock(&g_ListenRequestLock, oldIrql);
            
            // Không complete request này ngay
            return;
        }

        case IOCTL_AK_ADD_WHITELIST_PID:
        {
            KdPrint(("AtchKernel: IOCTL_AK_ADD_WHITELIST_PID - Not yet implemented.\n"));
            status = STATUS_NOT_IMPLEMENTED;
            break;
        }

        case IOCTL_AK_UPDATE_BLACKLIST:
        {
            KdPrint(("AtchKernel: IOCTL_AK_UPDATE_BLACKLIST - Not yet implemented.\n"));
            status = STATUS_NOT_IMPLEMENTED;
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}

// Hàm đẩy thông báo về Ring 3
void NotifyViolationToRing3(ULONG ProcessId, PCUNICODE_STRING ImagePath, ULONG ViolationType)
{
    KIRQL oldIrql;
    WDFREQUEST req = NULL;

    KeAcquireSpinLock(&g_ListenRequestLock, &oldIrql);
    req = g_PendingListenRequest;
    g_PendingListenRequest = NULL;
    KeReleaseSpinLock(&g_ListenRequestLock, oldIrql);

    if (req != NULL) {
        // Unmark cancelable
        NTSTATUS unmarkStatus = WdfRequestUnmarkCancelable(req);
        if (!NT_SUCCESS(unmarkStatus)) {
            req = NULL; // Request đã bị cancel
        }
    }

    if (req != NULL) {
        PMONITOR_LOG_ENTRY pLogEntry;
        NTSTATUS status = WdfRequestRetrieveOutputBuffer(req, sizeof(MONITOR_LOG_ENTRY), (PVOID*)&pLogEntry, NULL);
        if (NT_SUCCESS(status)) {
            pLogEntry->ConfiscatedProcessId = ProcessId;
            pLogEntry->ViolationType = ViolationType;
            
            if (ImagePath != NULL && ImagePath->Buffer != NULL) {
                size_t lenChars = ImagePath->Length / sizeof(WCHAR);
                if (lenChars > 255) lenChars = 255;
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
    return (ULONG)InterlockedOr((LONG volatile*)&g_ClientProcessId, 0);
}
