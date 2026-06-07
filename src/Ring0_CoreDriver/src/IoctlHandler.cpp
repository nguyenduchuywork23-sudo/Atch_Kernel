#include "../inc/IoctlHandler.h"
#include "../../include/SharedDef.h"

// Biến lưu trữ Request của Inverted Call
static WDFREQUEST g_PendingListenRequest = NULL;
static KSPIN_LOCK g_ListenRequestLock;
static volatile ULONG g_ClientProcessId = 0;

static volatile BOOLEAN g_IsExamLocked = FALSE;
static LARGE_INTEGER g_LastHeartbeatTime = {0};
static volatile BOOLEAN g_HeartbeatThreadRunning = FALSE;
static HANDLE g_HeartbeatThreadHandle = NULL;

void LockExam() {
    g_IsExamLocked = TRUE;
}
void UnlockExam() {
    g_IsExamLocked = FALSE;
    KeQuerySystemTime(&g_LastHeartbeatTime);
}
BOOLEAN IsExamLocked() {
    return g_IsExamLocked;
}

VOID HeartbeatThreadRoutine(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    LARGE_INTEGER delay;
    delay.QuadPart = -10000000LL; // 1 second

    while (g_HeartbeatThreadRunning)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
        
        if (g_ClientProcessId == 0) continue;

        LARGE_INTEGER currentTime;
        KeQuerySystemTime(&currentTime);

        if (g_LastHeartbeatTime.QuadPart != 0)
        {
            // If > 5 seconds (50,000,000 100-nanoseconds)
            if (currentTime.QuadPart - g_LastHeartbeatTime.QuadPart > 50000000LL)
            {
                if (!g_IsExamLocked) {
                    KdPrint(("AtchKernel: Heartbeat timeout! Locking exam.\n"));
                    LockExam();
                    UNICODE_STRING msg;
                    RtlInitUnicodeString(&msg, L"Heartbeat Timeout");
                    NotifyViolationToRing3(0, &msg, 7); // 7: HEARTBEAT_TIMEOUT
                }
            }
        }
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS InitializeIoctlQueue(WDFDEVICE Device)
{
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;

    KeInitializeSpinLock(&g_ListenRequestLock);

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
                KeQuerySystemTime(&g_LastHeartbeatTime);
                g_IsExamLocked = FALSE;
                
                if (!g_HeartbeatThreadRunning) {
                    g_HeartbeatThreadRunning = TRUE;
                    OBJECT_ATTRIBUTES objAttr;
                    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                    PsCreateSystemThread(&g_HeartbeatThreadHandle, THREAD_ALL_ACCESS, &objAttr, NULL, NULL, HeartbeatThreadRoutine, NULL);
                }
                KdPrint(("AtchKernel: Initialize Exam for PID %lu\n", pData->ClientProcessId));
            }
            break;
        }

        case IOCTL_AK_TERMINATE_EXAM:
        {
            KdPrint(("AtchKernel: Terminate Exam.\n"));
            InterlockedExchange((LONG volatile*)&g_ClientProcessId, 0);
            g_HeartbeatThreadRunning = FALSE;
            if (g_HeartbeatThreadHandle != NULL) {
                ZwClose(g_HeartbeatThreadHandle);
                g_HeartbeatThreadHandle = NULL;
            }
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_AK_SEND_HEARTBEAT:
        {
            KeQuerySystemTime(&g_LastHeartbeatTime);
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
