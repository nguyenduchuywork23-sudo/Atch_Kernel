#include "../inc/AntiDKOM.h"
#include "../inc/IoctlHandler.h"
#include "../inc/Callbacks.h"
#include <ntifs.h>

extern "C" __declspec(dllimport) PEPROCESS PsInitialSystemProcess;

#define SYSTEM_PID              ((HANDLE)4)
#define OFFSET_NOT_INITIALIZED  0xFFFFFFFFUL

// OMEGA-II M05: Volatile global replaces function-static (thread-safety under /kernel mode)
static volatile ULONG g_CachedListOffset = OFFSET_NOT_INITIALIZED;

ULONG GetActiveProcessLinksOffset() {
    PEPROCESS sysProc = PsInitialSystemProcess;
    if (!sysProc) return 0;
    
    HANDLE sysPid = SYSTEM_PID;
    
    // Scan EPROCESS for the PID
    for (ULONG i = 0; i < 0x800; i += sizeof(PVOID)) {
        HANDLE currentPid = 0;
        MM_COPY_ADDRESS pidAddr;
        pidAddr.VirtualAddress = (PUCHAR)sysProc + i;
        SIZE_T bytesCopied = 0;
        
        if (NT_SUCCESS(MmCopyMemory(&currentPid, pidAddr, sizeof(HANDLE), MM_COPY_MEMORY_VIRTUAL, &bytesCopied)) && currentPid == sysPid) {
            // Scan dynamically up to 0x40 bytes ahead to find the first valid LIST_ENTRY pointing back to itself
            for (ULONG j = sizeof(PVOID); j < 0x40; j += sizeof(PVOID)) {
                ULONG offset = i + j; 
                
                PLIST_ENTRY list = (PLIST_ENTRY)((PUCHAR)sysProc + offset);
                LIST_ENTRY listCopy;
                MM_COPY_ADDRESS listAddr;
                listAddr.VirtualAddress = list;
                
                if (NT_SUCCESS(MmCopyMemory(&listCopy, listAddr, sizeof(LIST_ENTRY), MM_COPY_MEMORY_VIRTUAL, &bytesCopied))) {
                    if (listCopy.Flink != NULL && listCopy.Blink != NULL) {
                        PLIST_ENTRY flinkBlink = NULL;
                        MM_COPY_ADDRESS flinkBlinkAddr;
                        flinkBlinkAddr.VirtualAddress = &listCopy.Flink->Blink;
                        
                        if (NT_SUCCESS(MmCopyMemory(&flinkBlink, flinkBlinkAddr, sizeof(PVOID), MM_COPY_MEMORY_VIRTUAL, &bytesCopied))) {
                            if (flinkBlink == list) {
                                return offset; // Found ActiveProcessLinks offset
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

BOOLEAN IsProcessInActiveList(PEPROCESS TargetProcess, ULONG ListOffset) {
    if (ListOffset == 0) return TRUE; 
    
    PEPROCESS sysProc = PsInitialSystemProcess;
    PLIST_ENTRY listHead = (PLIST_ENTRY)((PUCHAR)sysProc + ListOffset);
    
    ULONG iterations = 0;
    const ULONG MAX_PROCESSES = 8192; // Realistic max for linked-list walk
    
    __try {
        PLIST_ENTRY curr = NULL;
        MM_COPY_ADDRESS headAddress;
        headAddress.VirtualAddress = &listHead->Flink;
        SIZE_T bytesCopied = 0;
        
        NTSTATUS status = MmCopyMemory(&curr, headAddress, sizeof(PVOID), MM_COPY_MEMORY_VIRTUAL, &bytesCopied);
        if (!NT_SUCCESS(status) || curr == NULL) {
            return FALSE;
        }

        while (curr != listHead && curr != NULL && iterations < MAX_PROCESSES) {
            PEPROCESS proc = (PEPROCESS)((PUCHAR)curr - ListOffset);
            if (proc == TargetProcess) {
                return TRUE; // Found
            }
            
            PLIST_ENTRY nextNode = NULL;
            MM_COPY_ADDRESS address;
            address.VirtualAddress = &curr->Flink;
            status = MmCopyMemory(&nextNode, address, sizeof(PVOID), MM_COPY_MEMORY_VIRTUAL, &bytesCopied);
            if (!NT_SUCCESS(status)) {
                break;
            }
            
            curr = nextNode;
            iterations++;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Prevent BSOD if process terminates mid-traversal
    }
    
    return FALSE; // Not found, hidden!
}

void CheckAntiDKOM() {
    // OMEGA-II M05: Thread-safe offset caching with interlocked operations
    ULONG listOffset = (ULONG)InterlockedOr((LONG volatile*)&g_CachedListOffset, 0);
    if (listOffset == OFFSET_NOT_INITIALIZED) {
        listOffset = GetActiveProcessLinksOffset();
        InterlockedExchange((LONG volatile*)&g_CachedListOffset, (LONG)listOffset);
    }
    
    if (listOffset == 0) return;

    // OMEGA-II HIGH-11: Throttle DKOM scan to every 30 seconds.
    // Scanning 65536 PIDs every 1s causes severe CID table lock contention.
    static volatile LONGLONG g_LastDkomCheckTime = 0;
    // OMEGA-V-POWER-01: Use unbiased interrupt time (excludes sleep/hibernate)
    ULONGLONG nowUnbiased;
    KeQueryUnbiasedInterruptTime(&nowUnbiased);
    LONGLONG now = (LONGLONG)nowUnbiased;
    LONGLONG lastCheck = InterlockedCompareExchange64(&g_LastDkomCheckTime, 0, 0);
    if (now - lastCheck < 300000000LL) return; // 30 seconds
    InterlockedExchange64(&g_LastDkomCheckTime, now);

    // OMEGA-FINAL HIGH-09: Extend PID scan range to 0x40000 to cover heavily loaded systems
    for (ULONG pid = 4; pid < 0x40000; pid += 4) {
        PEPROCESS process = NULL;
        NTSTATUS status = PsLookupProcessByProcessId(UlongToHandle(pid), &process);
        
        if (NT_SUCCESS(status) && process != NULL) {
            // Process exists in PspCidTable. Cross-reference with ActiveProcessLinks.
            if (!IsProcessInActiveList(process, listOffset)) {
                // TOCTOU re-validation: the process may have legitimately exited
                // between the first PsLookupProcessByProcessId and the list walk.
                // We MUST drop our reference first, or the kernel cannot complete destruction!
                ObDereferenceObject(process);
                process = NULL;
                
                PEPROCESS recheck = NULL;
                NTSTATUS reStatus = PsLookupProcessByProcessId(UlongToHandle(pid), &recheck);
                if (NT_SUCCESS(reStatus) && recheck != NULL) {
                    // Process still in table. Verify if it is naturally terminating.
                    NTSTATUS exitStatus = PsGetProcessExitStatus(recheck);
                    if (exitStatus == STATUS_PENDING) {
                        // Process alive and not terminating — genuine DKOM hiding
                        AtchPrint(("Atch_Kernel: [AntiDKOM] Hidden Process Detected! PID: %lu\n", pid));
                        
                        ULONG examClientPid = GetExamClientProcessId();
                        if (examClientPid != 0) {
                            UNICODE_STRING msg;
                            RtlInitUnicodeString(&msg, L"Hidden Process Detected (DKOM)");
                            NotifyViolationToRing3(pid, &msg, ViolationType::VIOLATION_DKOM_HIDDEN);
                            ForceKillExamProcess((HANDLE)(ULONG_PTR)examClientPid);
                        }
                    } else {
                        AtchPrint(("Atch_Kernel: [AntiDKOM] PID %lu is terminating naturally, ignoring false positive.\n", pid));
                    }
                    ObDereferenceObject(recheck);
                } else {
                    // Process exited between checks — not a real DKOM violation
                    AtchPrint(("Atch_Kernel: [AntiDKOM] PID %lu exited during check, skipping.\n", pid));
                }
            }
            if (process != NULL) {
                ObDereferenceObject(process);
            }
        }
    }
}
