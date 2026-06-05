#include "../inc/AntiDKOM.h"
#include "../inc/IoctlHandler.h"
#include "../inc/Callbacks.h"

extern "C" PEPROCESS PsInitialSystemProcess;

ULONG GetActiveProcessLinksOffset() {
    PEPROCESS sysProc = PsInitialSystemProcess;
    if (!sysProc) return 0;
    
    HANDLE sysPid = (HANDLE)4;
    
    // Scan EPROCESS for the PID
    for (ULONG i = 0; i < 0x800; i += sizeof(PVOID)) {
        HANDLE* pPid = (HANDLE*)((PUCHAR)sysProc + i);
        if (*pPid == sysPid) {
            ULONG offset = i + sizeof(PVOID); 
            
            PLIST_ENTRY list = (PLIST_ENTRY)((PUCHAR)sysProc + offset);
            
            __try {
                if (list->Flink != NULL && list->Blink != NULL && list->Flink->Blink == list) {
                    return offset; // Found ActiveProcessLinks offset
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Ignore page faults
            }
        }
    }
    return 0;
}

BOOLEAN IsProcessInActiveList(PEPROCESS TargetProcess, ULONG ListOffset) {
    if (ListOffset == 0) return TRUE; 
    
    PEPROCESS sysProc = PsInitialSystemProcess;
    PLIST_ENTRY listHead = (PLIST_ENTRY)((PUCHAR)sysProc + ListOffset);
    PLIST_ENTRY curr = listHead->Flink;
    
    ULONG iterations = 0;
    const ULONG MAX_PROCESSES = 10000;
    
    while (curr != listHead && curr != NULL && iterations < MAX_PROCESSES) {
        PEPROCESS proc = (PEPROCESS)((PUCHAR)curr - ListOffset);
        if (proc == TargetProcess) {
            return TRUE; // Found
        }
        curr = curr->Flink;
        iterations++;
    }
    
    return FALSE; // Not found, hidden!
}

void CheckAntiDKOM() {
    static ULONG listOffset = 0xFFFFFFFF;
    if (listOffset == 0xFFFFFFFF) {
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
                KdPrint(("Atch_Kernel: [AntiDKOM] Hidden Process Detected! PID: %lu\n", pid));
                
                ULONG examClientPid = GetExamClientProcessId();
                if (examClientPid != 0) {
                    UNICODE_STRING msg;
                    RtlInitUnicodeString(&msg, L"Hidden Process Detected (DKOM)");
                    NotifyViolationToRing3(0, &msg, 6); // 6: DKOM_HIDDEN_PROCESS
                    ForceKillExamProcess((HANDLE)(ULONG_PTR)examClientPid);
                }
            }
            ObDereferenceObject(process);
        }
    }
}
