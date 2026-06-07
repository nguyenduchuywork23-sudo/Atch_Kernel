#include "../inc/AntiDKOM.h"
#include "../inc/IoctlHandler.h"
#include "../inc/Callbacks.h"

extern "C" PEPROCESS PsInitialSystemProcess;

#define SYSTEM_PID              ((HANDLE)4)
#define OFFSET_NOT_INITIALIZED  0xFFFFFFFFUL

ULONG GetActiveProcessLinksOffset() {
    PEPROCESS sysProc = PsInitialSystemProcess;
    if (!sysProc) return 0;
    
    HANDLE sysPid = SYSTEM_PID;
    
    // Scan EPROCESS for the PID
    for (ULONG i = 0; i < 0x800; i += sizeof(PVOID)) {
        __try {
            HANDLE* pPid = (HANDLE*)((PUCHAR)sysProc + i);
            if (*pPid == sysPid) {
                ULONG offset = i + sizeof(PVOID); 
                
                PLIST_ENTRY list = (PLIST_ENTRY)((PUCHAR)sysProc + offset);
                
                if (list->Flink != NULL && list->Blink != NULL && list->Flink->Blink == list) {
                    return offset; // Found ActiveProcessLinks offset
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Ignore page faults from probing EPROCESS memory
        }
    }
    return 0;
}

BOOLEAN IsProcessInActiveList(PEPROCESS TargetProcess, ULONG ListOffset) {
    if (ListOffset == 0) return TRUE; 
    
    PEPROCESS sysProc = PsInitialSystemProcess;
    PLIST_ENTRY listHead = (PLIST_ENTRY)((PUCHAR)sysProc + ListOffset);
    
    ULONG iterations = 0;
    const ULONG MAX_PROCESSES = 10000;
    
    __try {
        PLIST_ENTRY curr = listHead->Flink;
        while (curr != listHead && curr != NULL && iterations < MAX_PROCESSES) {
            PEPROCESS proc = (PEPROCESS)((PUCHAR)curr - ListOffset);
            if (proc == TargetProcess) {
                return TRUE; // Found
            }
            curr = curr->Flink;
            iterations++;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Prevent BSOD if process terminates mid-traversal
    }
    
    return FALSE; // Not found, hidden!
}

void CheckAntiDKOM() {
    static ULONG listOffset = OFFSET_NOT_INITIALIZED;
    if (listOffset == OFFSET_NOT_INITIALIZED) {
        listOffset = GetActiveProcessLinksOffset();
    }
    
    if (listOffset == 0) return;

    // Scan possible PIDs
    for (ULONG pid = 4; pid < 0x20000; pid += 4) {
        PEPROCESS process = NULL;
        NTSTATUS status = PsLookupProcessByProcessId(UlongToHandle(pid), &process);
        
        if (NT_SUCCESS(status) && process != NULL) {
            // Process exists in PspCidTable. Cross-reference with ActiveProcessLinks.
            if (!IsProcessInActiveList(process, listOffset)) {
                // TOCTOU re-validation: the process may have legitimately exited
                // between the first PsLookupProcessByProcessId and the list walk.
                PEPROCESS recheck = NULL;
                NTSTATUS reStatus = PsLookupProcessByProcessId(UlongToHandle(pid), &recheck);
                if (NT_SUCCESS(reStatus) && recheck != NULL) {
                    // Process still alive — genuine DKOM hiding
                    KdPrint(("Atch_Kernel: [AntiDKOM] Hidden Process Detected! PID: %lu\n", pid));
                    
                    ULONG examClientPid = GetExamClientProcessId();
                    if (examClientPid != 0) {
                        UNICODE_STRING msg;
                        RtlInitUnicodeString(&msg, L"Hidden Process Detected (DKOM)");
                        NotifyViolationToRing3(pid, &msg, VIOLATION_DKOM_HIDDEN);
                        ForceKillExamProcess((HANDLE)(ULONG_PTR)examClientPid);
                    }
                    ObDereferenceObject(recheck);
                } else {
                    // Process exited between checks — not a real DKOM violation
                    KdPrint(("Atch_Kernel: [AntiDKOM] PID %lu exited during check, skipping.\n", pid));
                    if (NT_SUCCESS(reStatus) && recheck != NULL) {
                        ObDereferenceObject(recheck);
                    }
                }
            }
            ObDereferenceObject(process);
        }
    }
}
