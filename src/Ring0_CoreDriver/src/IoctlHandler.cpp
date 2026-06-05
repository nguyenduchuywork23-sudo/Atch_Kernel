#include "../inc/IoctlHandler.h"
#include "../../include/SharedDef.h"

// Biến lưu trữ Request của Inverted Call
static WDFREQUEST g_PendingListenRequest = NULL;
static KSPIN_LOCK g_ListenRequestLock;
static ULONG g_ClientProcessId = 0;

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
    
    // Clear pending request if client closed
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ListenRequestLock, &oldIrql);
    if (g_PendingListenRequest != NULL) {
        WDFREQUEST req = g_PendingListenRequest;
        NTSTATUS unmarkStatus = WdfRequestUnmarkCancelable(req);
        if (NT_SUCCESS(unmarkStatus)) {
            g_PendingListenRequest = NULL;
            KeReleaseSpinLock(&g_ListenRequestLock, oldIrql);
            WdfRequestComplete(req, STATUS_CANCELLED);
        } else {
            g_PendingListenRequest = NULL;
            KeReleaseSpinLock(&g_ListenRequestLock, oldIrql);
        }
    } else {
        KeReleaseSpinLock(&g_ListenRequestLock, oldIrql);
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
                g_ClientProcessId = pData->ClientProcessId;
                KdPrint(("AtchKernel: Initialize Exam for PID %lu\n", g_ClientProcessId));
            }
            break;
        }

        case IOCTL_AK_TERMINATE_EXAM:
        {
            KdPrint(("AtchKernel: Terminate Exam.\n"));
            g_ClientProcessId = 0;
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_AK_SEND_HEARTBEAT:
        {
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
            
            if (g_PendingListenRequest != NULL) {
                // Đã có 1 request đang chờ, hủy request cũ
                WDFREQUEST oldReq = g_PendingListenRequest;
                NTSTATUS unmarkStatus = WdfRequestUnmarkCancelable(oldReq);
                g_PendingListenRequest = Request;
                KeReleaseSpinLock(&g_ListenRequestLock, oldIrql);
                
                if (NT_SUCCESS(unmarkStatus)) {
                    WdfRequestComplete(oldReq, STATUS_CANCELLED);
                }
            } else {
                g_PendingListenRequest = Request;
                KeReleaseSpinLock(&g_ListenRequestLock, oldIrql);
            }
            
            // Đánh dấu Request mới là cancelable
            WdfRequestMarkCancelableEx(Request, [](WDFREQUEST Req) {
                KIRQL irql;
                KeAcquireSpinLock(&g_ListenRequestLock, &irql);
                if (g_PendingListenRequest == Req) {
                    g_PendingListenRequest = NULL;
                }
                KeReleaseSpinLock(&g_ListenRequestLock, irql);
                WdfRequestComplete(Req, STATUS_CANCELLED);
            });
            
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
    if (g_PendingListenRequest != NULL) {
        req = g_PendingListenRequest;
        
        // Unmark cancelable
        NTSTATUS unmarkStatus = WdfRequestUnmarkCancelable(req);
        if (NT_SUCCESS(unmarkStatus)) {
            g_PendingListenRequest = NULL;
        } else {
            req = NULL; // Request đã bị cancel
        }
    }
    KeReleaseSpinLock(&g_ListenRequestLock, oldIrql);

    if (req != NULL) {
        PMONITOR_LOG_ENTRY pLogEntry;
        NTSTATUS status = WdfRequestRetrieveOutputBuffer(req, sizeof(MONITOR_LOG_ENTRY), (PVOID*)&pLogEntry, NULL);
        if (NT_SUCCESS(status)) {
            pLogEntry->ConfiscatedProcessId = ProcessId;
            pLogEntry->ViolationType = ViolationType;
            
            if (ImagePath != NULL && ImagePath->Buffer != NULL) {
                size_t lenChars = ImagePath->Length / sizeof(WCHAR);
                if (lenChars > 255) lenChars = 255;
                wcsncpy(pLogEntry->ImagePath, ImagePath->Buffer, lenChars);
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
    return g_ClientProcessId;
}
