#include "../inc/ThreadNotify.h"
#include "../inc/Callbacks.h"
#include "../inc/IoctlHandler.h"

// Callback function for thread creation/deletion
VOID ThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
)
{
    if (Create)
    {
        ULONG examClientPid = GetExamClientProcessId();

        // Basic heuristic for remote threads: thread created in a different process context
        if (ProcessId != PsGetCurrentProcessId())
        {
            KdPrint(("Atch_Kernel: ThreadNotify - Remote thread created. ProcessId: %p, ThreadId: %p\n", ProcessId, ThreadId));

            // Dual-Layer Defense against Thread Injection
            if (examClientPid != 0 && (ULONG)(ULONG_PTR)ProcessId == examClientPid)
            {
                // Kill the thread
                HANDLE threadHandle = NULL;
                OBJECT_ATTRIBUTES objAttr;
                CLIENT_ID clientId;

                InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                clientId.UniqueProcess = ProcessId;
                clientId.UniqueThread = ThreadId;

                NTSTATUS status = ZwOpenThread(&threadHandle, GENERIC_ALL, &objAttr, &clientId);
                if (status == STATUS_SUCCESS && threadHandle != NULL) {
                    ZwTerminateThread(threadHandle, STATUS_ACCESS_DENIED);
                    ZwClose(threadHandle);
                }

                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"Remote Thread Injection Blocked");
                NotifyViolationToRing3((ULONG)(ULONG_PTR)ProcessId, &msg, 3); // 3 could be THREAD_INJECTION
            }
        }
        else
        {
            KdPrint(("Atch_Kernel: ThreadNotify - Local thread created. ProcessId: %p, ThreadId: %p\n", ProcessId, ThreadId));
        }
    }
    else
    {
        KdPrint(("Atch_Kernel: ThreadNotify - Thread deleted. ProcessId: %p, ThreadId: %p\n", ProcessId, ThreadId));
    }
}

NTSTATUS InitThreadNotify()
{
    NTSTATUS status;

    // Register the thread notify callback
    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (NT_SUCCESS(status))
    {
        KdPrint(("Atch_Kernel: ThreadNotify successfully initialized.\n"));
    }
    else
    {
        KdPrint(("Atch_Kernel: Failed to initialize ThreadNotify (Status: 0x%X)\n", status));
    }

    return status;
}

void UnloadThreadNotify()
{
    NTSTATUS status;

    // Unregister the thread notify callback
    status = PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (NT_SUCCESS(status))
    {
        KdPrint(("Atch_Kernel: ThreadNotify successfully unloaded.\n"));
    }
    else
    {
        KdPrint(("Atch_Kernel: Failed to unload ThreadNotify (Status: 0x%X)\n", status));
    }
}
