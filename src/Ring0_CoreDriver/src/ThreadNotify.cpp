#include "../inc/ThreadNotify.h"
#include "../inc/Callbacks.h"
#include "../inc/IoctlHandler.h"

// Callback function for thread creation/deletion
static VOID ThreadNotifyCallback(
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

            // Skip if the creator is a Session 0 process (system services like csrss, smss, etc.)
            PEPROCESS currentProcess = IoGetCurrentProcess();
            ULONG creatorSessionId = 0;
            // PsGetProcessSessionId returns the session ID directly (ULONG)
            creatorSessionId = PsGetProcessSessionId(currentProcess);

            if (creatorSessionId == 0) {
                KdPrint(("Atch_Kernel: ThreadNotify - Skipping Session 0 system process thread creation.\n"));
            }
            // Dual-Layer Defense against Thread Injection (only for user-session processes)
            else if (examClientPid != 0 && (ULONG)(ULONG_PTR)ProcessId == examClientPid)
            {
                ForceKillExamThread(ProcessId, ThreadId);
                LockExam();

                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"Remote Thread Injection Blocked");
                NotifyViolationToRing3((ULONG)(ULONG_PTR)ProcessId, &msg, VIOLATION_THREAD_INJECTION);
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
