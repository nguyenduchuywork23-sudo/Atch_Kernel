#include "../inc/IoctlHandler.h"
#include "../../include/SharedDef.h"
#include "../inc/AntiDKOM.h"

// Biến lưu trữ Request của Inverted Call
static WDFREQUEST g_PendingListenRequest = NULL;
static KSPIN_LOCK g_ListenRequestLock;
static ULONG g_ClientProcessId = 0;

static PWCHAR* g_DynamicBlacklist = NULL;
static ULONG g_DynamicBlacklistCount = 0;
static FAST_MUTEX g_BlacklistMutex;

NTSTATUS InitializeIoctlQueue(WDFDEVICE Device)
{
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;

    KeInitializeSpinLock(&g_ListenRequestLock);
    ExInitializeFastMutex(&g_BlacklistMutex);

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
            // Trigger AntiDKOM check here
            CheckAntiDKOM();
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_AK_UPDATE_BLACKLIST:
        {
            if (InputBufferLength < sizeof(BLACKLIST_DATA)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PBLACKLIST_DATA pData;
            status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, (PVOID*)&pData, NULL);
            if (NT_SUCCESS(status)) {
                ULONG expectedSize = sizeof(BLACKLIST_DATA) + (pData->ItemCount * 256 * sizeof(WCHAR));
                if (InputBufferLength < expectedSize) {
                    status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }

                ExAcquireFastMutex(&g_BlacklistMutex);
                
                // Free old
                if (g_DynamicBlacklist != NULL) {
                    for (ULONG i = 0; i < g_DynamicBlacklistCount; i++) {
                        if (g_DynamicBlacklist[i]) {
                            ExFreePoolWithTag(g_DynamicBlacklist[i], 'LBKA');
                        }
                    }
                    ExFreePoolWithTag(g_DynamicBlacklist, 'LBKA');
                    g_DynamicBlacklist = NULL;
                }
                
                g_DynamicBlacklistCount = pData->ItemCount;
                if (g_DynamicBlacklistCount > 0) {
                    g_DynamicBlacklist = (PWCHAR*)ExAllocatePoolWithTag(NonPagedPoolNx, g_DynamicBlacklistCount * sizeof(PWCHAR), 'LBKA');
                    if (g_DynamicBlacklist) {
                        PWCHAR itemsArray = (PWCHAR)((PUCHAR)pData + sizeof(BLACKLIST_DATA));
                        for (ULONG i = 0; i < g_DynamicBlacklistCount; i++) {
                            g_DynamicBlacklist[i] = (PWCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, 256 * sizeof(WCHAR), 'LBKA');
                            if (g_DynamicBlacklist[i]) {
                                RtlCopyMemory(g_DynamicBlacklist[i], itemsArray + (i * 256), 256 * sizeof(WCHAR));
                                g_DynamicBlacklist[i][255] = L'\0';
                            }
                        }
                    } else {
                        g_DynamicBlacklistCount = 0;
                    }
                }
                
                ExReleaseFastMutex(&g_BlacklistMutex);
                KdPrint(("AtchKernel: Updated Blacklist with %lu items\n", g_DynamicBlacklistCount));
                status = STATUS_SUCCESS;
            }
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

BOOLEAN IsProcessBlacklisted(PCUNICODE_STRING ProcessName) {
    if (!ProcessName || !ProcessName->Buffer) return FALSE;
    BOOLEAN result = FALSE;
    
    // Extract filename
    USHORT lastSlashPos = 0;
    for (USHORT i = 0; i < ProcessName->Length / sizeof(WCHAR); i++) {
        if (ProcessName->Buffer[i] == L'\\') {
            lastSlashPos = i + 1;
        }
    }
    
    UNICODE_STRING fileName;
    fileName.Buffer = &ProcessName->Buffer[lastSlashPos];
    fileName.Length = ProcessName->Length - (lastSlashPos * sizeof(WCHAR));
    fileName.MaximumLength = fileName.Length;

    ExAcquireFastMutex(&g_BlacklistMutex);
    if (g_DynamicBlacklist != NULL) {
        for (ULONG i = 0; i < g_DynamicBlacklistCount; i++) {
            if (g_DynamicBlacklist[i]) {
                UNICODE_STRING blName;
                RtlInitUnicodeString(&blName, g_DynamicBlacklist[i]);
                if (RtlCompareUnicodeString(&fileName, &blName, TRUE) == 0) {
                    result = TRUE;
                    break;
                }
            }
        }
    }
    ExReleaseFastMutex(&g_BlacklistMutex);
    
    return result;
}
