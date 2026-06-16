#include "../inc/MemoryScanner.h"
#include "../inc/IoctlHandler.h" 

// ZwQueryVirtualMemory and MEMORY_BASIC_INFORMATION are provided by ntifs.h


#define MemoryBasicInformation 0
#ifndef MEM_COMMIT
#define MEM_COMMIT 0x1000
#endif
#ifndef MEM_PRIVATE
#define MEM_PRIVATE 0x20000
#endif
#ifndef MEM_MAPPED
#define MEM_MAPPED 0x40000
#endif
#ifndef MEM_IMAGE
#define MEM_IMAGE 0x1000000
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif

#ifndef PAGE_EXECUTE
#define PAGE_EXECUTE 0x10
#endif
#ifndef PAGE_EXECUTE_READ
#define PAGE_EXECUTE_READ 0x20
#endif
#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE 0x40
#endif
#ifndef PAGE_EXECUTE_WRITECOPY
#define PAGE_EXECUTE_WRITECOPY 0x80
#endif

NTSTATUS InitMemoryScanner() {
    return STATUS_SUCCESS;
}

// Helper: check if a page protection includes execute permission
static BOOLEAN IsExecutableProtection(ULONG Protect) {
    ULONG prot = Protect & 0xFF; // Strip PAGE_GUARD etc.
    return (prot == PAGE_EXECUTE ||
            prot == PAGE_EXECUTE_READ ||
            prot == PAGE_EXECUTE_READWRITE ||
            prot == PAGE_EXECUTE_WRITECOPY);
}

void CheckMemoryScanner() {
    ULONG clientPid = GetExamClientProcessId();
    if (clientPid == 0) return;

    // OMEGA-FINAL M01: Defensive IRQL assertion — ZwOpenProcess requires PASSIVE_LEVEL
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = UlongToHandle(clientPid);
    clientId.UniqueThread = NULL;

    // OMEGA-II M06: Least-privilege — only need query + VM read for ZwQueryVirtualMemory
    NTSTATUS status = ZwOpenProcess(&processHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);
    if (!NT_SUCCESS(status)) {
        return;
    }

    PVOID baseAddress = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    // OMEGA-VII-R4-003/R4-004: Iteration cap prevents heartbeat thread starvation.
    // Without this, scanning a process with many regions blocks all monitoring for minutes.
    ULONG regionCount = 0;
    const ULONG MAX_REGIONS = 100000;

    while (regionCount < MAX_REGIONS) {
        regionCount++;
        status = ZwQueryVirtualMemory(processHandle, baseAddress, (MEMORY_INFORMATION_CLASS)MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
        if (!NT_SUCCESS(status) || status == STATUS_INVALID_PARAMETER) {
            break;
        }

        if (mbi.State == MEM_COMMIT && IsExecutableProtection(mbi.Protect)) {

            // === LAYER 1: Private executable memory ===
            // Manual Mapping / Reflective DLL Injection / Shellcode
            if (mbi.Type == MEM_PRIVATE) {
                AtchPrint(("AtchKernel: [CRITICAL] Private Executable Memory at %p (Prot=0x%X)\n", mbi.BaseAddress, mbi.Protect));
                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"Private Executable Memory (Manual Map/Shellcode)");
                NotifyViolationToRing3(clientPid, &msg, ViolationType::VIOLATION_MANUAL_MAPPING);
                LockExam();
                break;
            }

            // === LAYER 2: Mapped executable memory ===
            // Phantom DLL Hollowing / NtCreateSection+NtMapViewOfSection injection
            // Legitimate apps almost never execute from MEM_MAPPED regions
            if (mbi.Type == MEM_MAPPED) {
                AtchPrint(("AtchKernel: [CRITICAL] Mapped Executable Memory at %p (Prot=0x%X)\n", mbi.BaseAddress, mbi.Protect));
                UNICODE_STRING msg;
                RtlInitUnicodeString(&msg, L"Mapped Executable Memory (Phantom DLL Hollowing)");
                NotifyViolationToRing3(clientPid, &msg, ViolationType::VIOLATION_MANUAL_MAPPING);
                LockExam();
                break;
            }

            // === LAYER 3: Image memory with RWX ===
            // Module Stomping / Mockingjay technique
            // Legitimate compiled DLLs NEVER have PAGE_EXECUTE_READWRITE at runtime
            if (mbi.Type == MEM_IMAGE) {
                ULONG prot = mbi.Protect & 0xFF;
                if (prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY) {
                    AtchPrint(("AtchKernel: [CRITICAL] RWX Image Memory at %p (Prot=0x%X) - Module Stomping\n", mbi.BaseAddress, mbi.Protect));
                    UNICODE_STRING msg;
                    RtlInitUnicodeString(&msg, L"RWX Image Memory (Module Stomping/Mockingjay)");
                    NotifyViolationToRing3(clientPid, &msg, ViolationType::VIOLATION_MANUAL_MAPPING);
                    LockExam();
                    break;
                }
            }
        }

        // Move to the next region
        PVOID nextAddress = (PVOID)((PUCHAR)mbi.BaseAddress + mbi.RegionSize);
        if (nextAddress <= mbi.BaseAddress) {
            break; // Wrap-around
        }
        baseAddress = nextAddress;
        
        // Avoid scanning kernel space
        if (baseAddress >= MM_HIGHEST_USER_ADDRESS) {
            break;
        }
    }

    ZwClose(processHandle);
}
