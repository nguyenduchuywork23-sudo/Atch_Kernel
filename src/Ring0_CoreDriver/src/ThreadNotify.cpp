#include "../inc/ThreadNotify.h"

// Callback function for thread creation/deletion
VOID ThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
)
{
    if (Create)
    {
        // Basic heuristic for remote threads: thread created in a different process context
        if (ProcessId != PsGetCurrentProcessId())
        {
            KdPrint(("Atch_Kernel: ThreadNotify - Remote thread created. ProcessId: %p, ThreadId: %p\n", ProcessId, ThreadId));
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
