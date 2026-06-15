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

        // Detect remote threads: thread created in a different process context
        if (ProcessId != PsGetCurrentProcessId())
        {
            // If the target is the exam process, block ALL remote thread creation
            // regardless of session (closes Confused Deputy via Session 0 processes)
            if (examClientPid != 0 && (ULONG)(ULONG_PTR)ProcessId == examClientPid)
            {
                AtchPrint(("Atch_Kernel: ThreadNotify - BLOCKED remote thread into exam process! Creator PID: %p, ThreadId: %p\n",
                    PsGetCurrentProcessId(), ThreadId));
                
                ForceKillExamThread(PsGetCurrentProcessId(), ThreadId);
                LockExam();

                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"Remote Thread Injection Blocked");
                NotifyViolationToRing3((ULONG)(ULONG_PTR)ProcessId, &msg, ViolationType::VIOLATION_THREAD_INJECTION);
            }
            else
            {
                AtchPrint(("Atch_Kernel: ThreadNotify - Remote thread created. ProcessId: %p, ThreadId: %p\n", ProcessId, ThreadId));
            }
        }
        else
        {
            AtchPrint(("Atch_Kernel: ThreadNotify - Local thread created. ProcessId: %p, ThreadId: %p\n", ProcessId, ThreadId));
        }
    }
    else
    {
        AtchPrint(("Atch_Kernel: ThreadNotify - Thread deleted. ProcessId: %p, ThreadId: %p\n", ProcessId, ThreadId));
    }
}

static volatile LONG g_ThreadNotifyRegistered = 0;

NTSTATUS InitThreadNotify()
{
    NTSTATUS status;

    // Register the thread notify callback
    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (NT_SUCCESS(status))
    {
        InterlockedExchange(&g_ThreadNotifyRegistered, 1);
        AtchPrint(("Atch_Kernel: ThreadNotify successfully initialized.\n"));
    }
    else
    {
        AtchPrint(("Atch_Kernel: Failed to initialize ThreadNotify (Status: 0x%X)\n", status));
    }

    return status;
}

void UnloadThreadNotify()
{
    // Guard: only unregister if we successfully registered
    if (InterlockedOr(&g_ThreadNotifyRegistered, 0) == 0) {
        return;
    }

    NTSTATUS status;

    // Unregister the thread notify callback
    status = PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (NT_SUCCESS(status))
    {
        InterlockedExchange(&g_ThreadNotifyRegistered, 0);
        AtchPrint(("Atch_Kernel: ThreadNotify successfully unloaded.\n"));
    }
    else
    {
        AtchPrint(("Atch_Kernel: Failed to unload ThreadNotify (Status: 0x%X)\n", status));
    }

}
