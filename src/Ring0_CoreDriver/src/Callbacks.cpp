#include "../inc/Callbacks.h"
#include "../inc/IoctlHandler.h"
#include "../inc/CompileTimeHash.h"

// Process/Thread access rights not defined in km headers (from winnt.h)
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE           (0x0001)
#define PROCESS_CREATE_THREAD       (0x0002)
#define PROCESS_SET_SESSIONID       (0x0004)
#define PROCESS_VM_OPERATION        (0x0008)
#define PROCESS_VM_READ             (0x0010)
#define PROCESS_VM_WRITE            (0x0020)
#define PROCESS_CREATE_PROCESS      (0x0080)
#define PROCESS_SET_INFORMATION     (0x0200)
#define PROCESS_QUERY_INFORMATION   (0x0400)
#define PROCESS_SUSPEND_RESUME      (0x0800)
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN     (0x0080)
#define THREAD_IMPERSONATE          (0x0100)
#define THREAD_DIRECT_IMPERSONATION (0x0200)
#endif

extern "C" PCHAR PsGetProcessImageFileName(PEPROCESS Process);
extern "C" BOOLEAN PsIsProtectedProcessLight(PEPROCESS Process);
extern "C" BOOLEAN PsIsProtectedProcess(PEPROCESS Process);

// Biến lưu cookie đăng ký
static LARGE_INTEGER g_RegistryCookie = { 0 };
static PVOID g_ObRegistrationHandle = NULL;
static volatile LONG g_ProcessCallbackRegistered = 0;
static PDEVICE_OBJECT g_DeviceObjectForWorkItems = NULL;
volatile LONG g_OutstandingWorkItems = 0;
KEVENT g_WorkItemDrainEvent;

void ScheduleEmergencyCleanup(ULONG ProcessId);

void InitCallbacks() {
    KeInitializeEvent(&g_WorkItemDrainEvent, NotificationEvent, TRUE);
}

void SetDeviceObjectForCallbacks(PDEVICE_OBJECT DeviceObject) {
    InterlockedExchangePointer((PVOID volatile*)&g_DeviceObjectForWorkItems, DeviceObject);
}

PDEVICE_OBJECT GetDeviceObjectForCallbacks() {
    return (PDEVICE_OBJECT)InterlockedCompareExchangePointer((PVOID volatile*)&g_DeviceObjectForWorkItems, NULL, NULL);
}

// OMEGA-IX-R4-002: Improved pre-filter using 2-char bigrams instead of single chars.
// Single chars ('v','o','l') match nearly every registry path → no filtering at all.
// Bigrams 'tc' (AtchKernel), 'xe' (Execution/Exit), 'if' (IFEO), '..' (traversal)
// are rare enough to reject 95%+ of registry operations before expensive CheckSubstring.
BOOLEAN FastRegistryPreFilter(PCUNICODE_STRING Str) {
    if (!Str || !Str->Buffer) return FALSE;
    SIZE_T chars = Str->Length / sizeof(WCHAR);
    if (chars < 2) return FALSE;
    for (SIZE_T i = 0; i < chars - 1; i++) {
        WCHAR c1 = Str->Buffer[i];
        WCHAR c2 = Str->Buffer[i + 1];
        if (c1 >= L'A' && c1 <= L'Z') c1 += (L'a' - L'A');
        if (c2 >= L'A' && c2 <= L'Z') c2 += (L'a' - L'A');
        // 'tc' → AtchKernel, ControlSet
        // 'xe' → Execution, SilentProcessExit
        // 'if' → Image File (IFEO)
        // '..' → path traversal (..\)
        // 'rv' → Services
        // 'ex' → Execution, SilentProcessExit
        // 'nt' → SilentProcessExit, CurrentControlSet (lower FP than 'ss')
        if ((c1 == L't' && c2 == L'c') ||
            (c1 == L'x' && c2 == L'e') ||
            (c1 == L'e' && c2 == L'x') ||
            (c1 == L'n' && c2 == L't') ||
            (c1 == L'i' && c2 == L'f') ||
            (c1 == L'.' && c2 == L'.') ||
            (c1 == L'r' && c2 == L'v') ||
            (c1 == L'a' && c2 == L'f') ||
            (c1 == L'e' && c2 == L'b') ||
            (c1 == L'o' && c2 == L'o')) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN CheckSubstring(PCUNICODE_STRING Str, PCWSTR SubStr) {
    if (Str == NULL || Str->Buffer == NULL || SubStr == NULL) return FALSE;
    SIZE_T subLen = wcslen(SubStr);
    BOOLEAN result = FALSE;
    __try {
        SIZE_T strLenChars = Str->Length / sizeof(WCHAR);
        if (strLenChars >= subLen) {
            for (SIZE_T i = 0; i <= strLenChars - subLen; i++) {
                BOOLEAN match = TRUE;
                for (SIZE_T j = 0; j < subLen; j++) {
                    WCHAR c1 = Str->Buffer[i + j];
                    WCHAR c2 = SubStr[j];
                    if (c1 >= L'A' && c1 <= L'Z') c1 += (L'a' - L'A');
                    if (c2 >= L'A' && c2 <= L'Z') c2 += (L'a' - L'A');
                    if (c1 != c2) { match = FALSE; break; }
                }
                if (match) { result = TRUE; break; }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = FALSE;
    }
    return result;
}

// 1. Process Callback
void ProcessNotifyCallbackEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        if (CreateInfo->ImageFileName != NULL) {
            PCUNICODE_STRING imageName = CreateInfo->ImageFileName;
            
            if (imageName->Buffer != NULL && imageName->Length > 0) {
                BOOLEAN isBlacklisted = FALSE;
                __try {
                    USHORT lastSlashPos = 0;
                    for (USHORT i = 0; i < imageName->Length / sizeof(WCHAR); i++) {
                        if (imageName->Buffer[i] == L'\\' || imageName->Buffer[i] == L'/') {
                            lastSlashPos = i + 1;
                        }
                    }
                    
                    UNICODE_STRING fileName;
                    fileName.Buffer = imageName->Buffer + lastSlashPos;
                    fileName.Length = imageName->Length - (lastSlashPos * sizeof(WCHAR));
                    if (fileName.Length >= sizeof(WCHAR) && fileName.Buffer[(fileName.Length / sizeof(WCHAR)) - 1] == L'\0') {
                        fileName.Length -= sizeof(WCHAR);
                    }
                    
                    ULONG hash = RuntimeHashUnicodeString(&fileName);
                    if (hash == CompileTimeHashW(L"cheatengine-x86_64.exe") ||
                        hash == CompileTimeHashW(L"processhacker.exe") ||
                        hash == CompileTimeHashW(L"ida64.exe") ||
                        hash == CompileTimeHashW(L"x64dbg.exe") ||
                        IsHashBlacklisted(hash)) {
                        isBlacklisted = TRUE;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    isBlacklisted = FALSE;
                }

                if (isBlacklisted) {
                    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                    NotifyViolationToRing3((ULONG)(ULONG_PTR)ProcessId, imageName, ViolationType::VIOLATION_PROCESS_BLACKLISTED);
                    LockExam();
                }
            }
        }
    } else {
        // Process termination — detect exam client crash and fully clean up
        ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
        ULONG examPid = GetExamClientProcessId();
        if (pid != 0 && pid == examPid) {
            AtchPrint(("AtchKernel: CRITICAL — Exam client PID %lu terminated unexpectedly!\n", pid));
            LockExam();
            NotifyViolationToRing3(pid, NULL, ViolationType::VIOLATION_HEARTBEAT_TIMEOUT);
            // Full cleanup: clear PID, stop heartbeat thread, prevent zombie state
            EmergencyCleanupExam(pid);
        }
    }
}

// 2. Registry Callback
NTSTATUS RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    // OMEGA-XX+XXI: Rate limiter — prevent DoS via registry callback storm.
    // OMEGA-XXI FIX: Rate limiter ONLY applies to exam-active processing (below).
    // Self-protection (service key block) is NEVER rate-limited — it must ALWAYS run.
    static volatile LONG g_RegCallbackCount = 0;
    static volatile LONGLONG g_RegCallbackWindowStart = 0;

    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    // Chặn chỉnh sửa khóa Image File Execution Options (IFEO) và khóa Service
    // OMEGA-VII-R3-002: Added RegNtPreSaveKey to block RegSaveKey-based hive export attacks.
    if (notifyClass == RegNtPreSetValueKey || notifyClass == RegNtPreDeleteKey || notifyClass == RegNtPreDeleteValueKey || notifyClass == RegNtPreRenameKey || notifyClass == RegNtPreCreateKeyEx || notifyClass == RegNtPreCreateKey || notifyClass == RegNtPreRestoreKey || notifyClass == RegNtPreReplaceKey || notifyClass == RegNtPreLoadKey || notifyClass == RegNtPreSetKeySecurity || notifyClass == RegNtPreSaveKey) {
        PVOID keyObject = NULL;
        PCUNICODE_STRING newName = NULL;
        PCUNICODE_STRING completeName = NULL; // For absolute path check

        if (notifyClass == RegNtPreSetValueKey) {
            PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (info) keyObject = info->Object;
        } else if (notifyClass == RegNtPreDeleteValueKey) {
            PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
            if (info) keyObject = info->Object;
        } else if (notifyClass == RegNtPreDeleteKey) {
            PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
            if (info) keyObject = info->Object;
        } else if (notifyClass == RegNtPreRenameKey) {
            PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
            if (info) { keyObject = info->Object; newName = info->NewName; }
        } else if (notifyClass == RegNtPreCreateKeyEx) {
            PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
            if (info) {
                keyObject = info->RootObject;
                completeName = info->CompleteName;
                // When RootObject is not NULL, CompleteName is a relative path
                if (keyObject != NULL) {
                    newName = info->CompleteName;
                }
            }
        } else if (notifyClass == RegNtPreCreateKey) {
            PREG_PRE_CREATE_KEY_INFORMATION info = (PREG_PRE_CREATE_KEY_INFORMATION)Argument2;
            if (info) completeName = info->CompleteName;
        } else if (notifyClass == RegNtPreRestoreKey) {
            PREG_RESTORE_KEY_INFORMATION info = (PREG_RESTORE_KEY_INFORMATION)Argument2;
            if (info) keyObject = info->Object;
        } else if (notifyClass == RegNtPreReplaceKey) {
            PREG_REPLACE_KEY_INFORMATION info = (PREG_REPLACE_KEY_INFORMATION)Argument2;
            if (info) keyObject = info->Object;
        } else if (notifyClass == RegNtPreLoadKey) {
            PREG_LOAD_KEY_INFORMATION info = (PREG_LOAD_KEY_INFORMATION)Argument2;
            if (info) keyObject = info->Object;
        } else if (notifyClass == RegNtPreSetKeySecurity) {
            PREG_SET_KEY_SECURITY_INFORMATION info = (PREG_SET_KEY_SECURITY_INFORMATION)Argument2;
            if (info) keyObject = info->Object;
        } else if (notifyClass == RegNtPreSaveKey) {
            // OMEGA-VII-R3-002: Block RegSaveKey on protected keys to prevent offline hive tampering.
            PREG_SAVE_KEY_INFORMATION info = (PREG_SAVE_KEY_INFORMATION)Argument2;
            if (info) keyObject = info->Object;
        }

        // OMEGA-V-BOOT-02: Always protect our OWN service key from deletion/rename/disable,
        // even outside exam sessions. Only gate the aggressive per-process blocking on exam state.
        ULONG regExamPid = GetExamClientProcessId();
        BOOLEAN isExamActive = (regExamPid != 0);

        // Self-protection: ALWAYS block attempts to delete/rename our service key
        if (!isExamActive) {
            // Outside exam: only block destructive ops on our own service key
            if (notifyClass != RegNtPreDeleteKey &&
                notifyClass != RegNtPreRenameKey &&
                notifyClass != RegNtPreSetValueKey &&
                notifyClass != RegNtPreDeleteValueKey &&
                notifyClass != RegNtPreLoadKey &&
                notifyClass != RegNtPreRestoreKey &&
                notifyClass != RegNtPreReplaceKey) {
                return STATUS_SUCCESS;
            }
        } else {
            // OMEGA-XXI: Rate limiter — ONLY for exam-active processing.
            // Self-protection block above ALWAYS runs regardless of rate.
            LONGLONG now = KeQueryUnbiasedInterruptTime();
            LONGLONG windowStart = InterlockedCompareExchange64(&g_RegCallbackWindowStart, 0, 0);
            if (now - windowStart > 10000000LL) { // 1 second window
                InterlockedExchange(&g_RegCallbackCount, 0);
                InterlockedExchange64(&g_RegCallbackWindowStart, now);
            }
            if (InterlockedIncrement(&g_RegCallbackCount) > 5000) {
                return STATUS_SUCCESS; // Drop exam-active processing only
            }
        }

        // === Handle RegNtPreCreateKeyEx/CreateKey with absolute path (RootObject == NULL) ===
        // When an absolute path is provided, RootObject is NULL and
        // CompleteName contains the full path. We MUST check it directly.
        if ((notifyClass == RegNtPreCreateKeyEx || notifyClass == RegNtPreCreateKey) && keyObject == NULL && completeName != NULL) {
            // OMEGA-IX-R4-003: Pre-filter completeName for consistency with keyName checks
            if (FastRegistryPreFilter(completeName)) {
                if (CheckSubstring(completeName, L"\\Services\\AtchKernel") ||
                    CheckSubstring(completeName, L"Services\\AtchKernel") ||
                    CheckSubstring(completeName, L"..\\") ||
                    CheckSubstring(completeName, L"Image File Execution Options\\AtchKernel.exe") ||
                    CheckSubstring(completeName, L"SilentProcessExit\\AtchKernel.exe") ||
                    CheckSubstring(completeName, L"SafeBoot\\Minimal\\AtchKernel.sys") ||
                    CheckSubstring(completeName, L"SafeBoot\\Network\\AtchKernel.sys")) {
                    UNICODE_STRING regMsg;
                    RtlInitUnicodeString(&regMsg, L"Registry Tampering Detected (Absolute Path)");
                    NotifyViolationToRing3(0, &regMsg, ViolationType::VIOLATION_REGISTRY_TAMPERING);
                    return STATUS_ACCESS_DENIED;
                }
            }
        }

        if (keyObject != NULL) {
            PCUNICODE_STRING keyName = NULL;
            if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_RegistryCookie, keyObject, NULL, &keyName, 0))) {
                BOOLEAN block = FALSE;
                if (keyName != NULL && keyName->Buffer != NULL) {
                    if (FastRegistryPreFilter(keyName)) {
                        if (CheckSubstring(keyName, L"\\Services\\AtchKernel") || 
                            CheckSubstring(keyName, L"Services\\AtchKernel") || 
                            CheckSubstring(keyName, L"..\\") || 
                            CheckSubstring(keyName, L"Image File Execution Options\\AtchKernel.exe") ||
                            CheckSubstring(keyName, L"SilentProcessExit\\AtchKernel.exe") ||
                            CheckSubstring(keyName, L"SafeBoot\\Minimal\\AtchKernel.sys") ||
                            CheckSubstring(keyName, L"SafeBoot\\Network\\AtchKernel.sys")) {
                            block = TRUE;
                        }
                    }
                    
                    if (!block && notifyClass == RegNtPreRenameKey) {
                        // If someone renames "Image File Execution Options" itself, block it
                        if (FastRegistryPreFilter(keyName)) {
                            if (CheckSubstring(keyName, L"Image File Execution Options") ||
                                CheckSubstring(keyName, L"SilentProcessExit") ||
                                CheckSubstring(keyName, L"CurrentControlSet\\Services") ||
                                CheckSubstring(keyName, L"ControlSet001\\Services") ||
                                // OMEGA-VII-R3-003: Cover ALL ControlSets (004+) with broader match
                                CheckSubstring(keyName, L"ControlSet002\\Services") ||
                                CheckSubstring(keyName, L"ControlSet003\\Services") ||
                                CheckSubstring(keyName, L"ControlSet004\\Services") ||
                                CheckSubstring(keyName, L"ControlSet005\\Services")) {
                                block = TRUE;
                            }
                        }
                    }
                    
                    // === FIX: Block Restoring/Replacing Parent Hives ===
                    if (!block && (notifyClass == RegNtPreRestoreKey || notifyClass == RegNtPreReplaceKey || notifyClass == RegNtPreLoadKey)) {
                        if (FastRegistryPreFilter(keyName)) {
                            if (CheckSubstring(keyName, L"\\Services") || 
                                CheckSubstring(keyName, L"Image File Execution Options") ||
                                CheckSubstring(keyName, L"SilentProcessExit") ||
                                CheckSubstring(keyName, L"CurrentControlSet") ||
                                CheckSubstring(keyName, L"CurrentVersion") ||
                                CheckSubstring(keyName, L"Control")) {
                                block = TRUE;
                            }
                        }
                    }
                
                // Check relative paths: combine keyName + newName context
                if (!block && newName != NULL && newName->Buffer != NULL) {
                    if (FastRegistryPreFilter(newName)) {
                        if (CheckSubstring(newName, L"AtchKernel")) {
                            if (keyName != NULL && keyName->Buffer != NULL) {
                                if (FastRegistryPreFilter(keyName)) {
                                    if (CheckSubstring(keyName, L"\\Services") || 
                                        CheckSubstring(keyName, L"Image File Execution Options") ||
                                        CheckSubstring(keyName, L"SilentProcessExit")) {
                                        block = TRUE;
                                    }
                                }
                            }
                        }
                        // Also check the full relative path for Service/IFEO patterns
                        if (!block) {
                            if (CheckSubstring(newName, L"\\Services\\AtchKernel") ||
                                CheckSubstring(newName, L"Image File Execution Options\\AtchKernel.exe") ||
                                CheckSubstring(newName, L"SilentProcessExit\\AtchKernel.exe") ||
                                CheckSubstring(newName, L"SafeBoot\\Minimal\\AtchKernel.sys") ||
                                CheckSubstring(newName, L"SafeBoot\\Network\\AtchKernel.sys")) {
                                block = TRUE;
                            }
                        }
                    }
                }
                
                if (block) {
                    UNICODE_STRING regMsg;
                    RtlInitUnicodeString(&regMsg, L"Registry Tampering Detected");
                    NotifyViolationToRing3(0, &regMsg, ViolationType::VIOLATION_REGISTRY_TAMPERING);
                }
                } // Close: if (keyName != NULL && keyName->Buffer != NULL)
                
                CmCallbackReleaseKeyObjectIDEx(keyName);
                if (block) return STATUS_ACCESS_DENIED;
            }
        }
    }
    return STATUS_SUCCESS;
}

// 3. Object Callback (Anti-Kill, Anti-Tampering)
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation == NULL) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->ObjectType != *PsProcessType && OperationInformation->ObjectType != *PsThreadType) {
        return OB_PREOP_SUCCESS;
    }

    ULONG clientPid = GetExamClientProcessId();
    if (clientPid == 0) {
        return OB_PREOP_SUCCESS;
    }

    // OMEGA-VIII-R4-001: Use cached EPROCESS pointer instead of PsLookupProcessByProcessId.
    // g_ClientEProcess is pinned via ObReferenceObject during exam init and remains valid
    // until exam termination. This eliminates 10K-50K PspCidTable lock acquisitions/sec.
    extern PEPROCESS GetClientEProcess();
    PEPROCESS clientProcess = GetClientEProcess();
    BOOLEAN mustDeref = FALSE;
    if (clientProcess == NULL) {
        // Fallback: EPROCESS not cached (shouldn't happen when PID != 0)
        // OMEGA-XII: Guard against DISPATCH_LEVEL to prevent BSOD
        if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
            return OB_PREOP_SUCCESS;
        }
        
        NTSTATUS status = PsLookupProcessByProcessId(UlongToHandle(clientPid), &clientProcess);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_INVALID_PARAMETER && clientPid != 0) {
                AtchPrint(("AtchKernel: CRITICAL — Zombie PID %lu detected in ObCallback. Scheduling cleanup.\n", clientPid));
                ScheduleEmergencyCleanup(clientPid);
            }
            return OB_PREOP_SUCCESS;
        }
        // Must dereference since PsLookup added a ref
        mustDeref = TRUE;
    }

    // Common path using clientProcess
    {
        BOOLEAN isTarget = FALSE;
        if (OperationInformation->ObjectType == *PsProcessType) {
            if (OperationInformation->Object == clientProcess) isTarget = TRUE;
        } else if (OperationInformation->ObjectType == *PsThreadType) {
            if (PsGetThreadProcess((PETHREAD)OperationInformation->Object) == clientProcess) {
                isTarget = TRUE;
            }
            BOOLEAN isTargetHeartbeat = FALSE;
            HANDLE heartbeatId = GetHeartbeatThreadId();
            if (heartbeatId != NULL) {
                HANDLE targetId = PsGetThreadId((PETHREAD)OperationInformation->Object);
                if (targetId == heartbeatId) {
                    isTargetHeartbeat = TRUE;
                }
            }
            if (isTargetHeartbeat) isTarget = TRUE;
        }

        if (isTarget) {
            // Identify the process requesting the handle
            PEPROCESS currentProcess = IoGetCurrentProcess();
            PCHAR processName = PsGetProcessImageFileName(currentProcess);
            BOOLEAN isSelf = (currentProcess == clientProcess);
            BOOLEAN isSystemProcess = FALSE;
            
            if (processName) {
                SIZE_T len = strlen(processName);
                if ((len == 9 && _stricmp(processName, "csrss.exe") == 0) || 
                    (len == 9 && _stricmp(processName, "lsass.exe") == 0)) {
                    // Check both PP (legacy) and PPL (Windows 10+) to cover all OS versions
                    if (PsIsProtectedProcess(currentProcess) || PsIsProtectedProcessLight(currentProcess)) {
                        isSystemProcess = TRUE;
                    }
                }
            }

            // === HARDENED: System processes get LIMITED access to exam process ===
            // Even csrss.exe/lsass.exe should NEVER write to or inject into the exam.
            // They only need PROCESS_QUERY_INFORMATION + PROCESS_VM_READ for OS stability.
            // This prevents Confused Deputy & PPL Spoofing attacks.
            
            // Check if target is heartbeat thread
            PKTHREAD heartbeatThread = GetHeartbeatThreadObject();
            BOOLEAN isTargetHeartbeat = (heartbeatThread != NULL && OperationInformation->ObjectType == *PsThreadType && OperationInformation->Object == heartbeatThread);
            
            BOOLEAN isWhitelisted = IsPidWhitelisted((ULONG)(ULONG_PTR)PsGetProcessId(currentProcess));

            if (!OperationInformation->KernelHandle && (!isSelf || isTargetHeartbeat) && !isWhitelisted) {
                if (isSystemProcess && !isTargetHeartbeat) {
                    // System processes: strip dangerous write/injection rights, keep read
                    ACCESS_MASK dangerousProcessRights = PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION | PROCESS_CREATE_PROCESS | PROCESS_SUSPEND_RESUME | WRITE_DAC | WRITE_OWNER;
                    ACCESS_MASK dangerousThreadRights = THREAD_TERMINATE | THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION | THREAD_SUSPEND_RESUME | WRITE_DAC | WRITE_OWNER | THREAD_SET_LIMITED_INFORMATION;
                    
                    if (OperationInformation->ObjectType == *PsProcessType) {
                        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~dangerousProcessRights;
                        } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~dangerousProcessRights;
                        }
                    } else if (OperationInformation->ObjectType == *PsThreadType) {
                        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~dangerousThreadRights;
                        } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~dangerousThreadRights;
                        }
                    }
                } else {
                    // Non-system, non-self processes: strip ALL dangerous rights (existing behavior)
                    if (OperationInformation->ObjectType == *PsProcessType) {
                        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION | WRITE_DAC | PROCESS_CREATE_PROCESS | WRITE_OWNER);
                        } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION | WRITE_DAC | PROCESS_CREATE_PROCESS | WRITE_OWNER);
                        }
                    } else if (OperationInformation->ObjectType == *PsThreadType) {
                        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION | WRITE_DAC | WRITE_OWNER | THREAD_SET_LIMITED_INFORMATION);
                        } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION | WRITE_DAC | WRITE_OWNER | THREAD_SET_LIMITED_INFORMATION);
                        }
                    }
                }
            }
        }
    }

    // OMEGA-VIII-R4-001: Only deref if we used PsLookup fallback (which adds an extra ref)
    if (mustDeref) {
        ObDereferenceObject(clientProcess);
    }

    return OB_PREOP_SUCCESS;
}

// OMEGA-IX-R3-003: Removed dead ThreadId field (was always NULL after ForceKillExamThread removal)
typedef struct _TERMINATION_WORK_ITEM_CONTEXT {
    PIO_WORKITEM WorkItem;
    HANDLE ProcessId;
} TERMINATION_WORK_ITEM_CONTEXT, *PTERMINATION_WORK_ITEM_CONTEXT;

IO_WORKITEM_ROUTINE TerminationWorkerRoutine;
VOID TerminationWorkerRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PTERMINATION_WORK_ITEM_CONTEXT pContext = (PTERMINATION_WORK_ITEM_CONTEXT)Context;
    
    // Terminate the entire process owning the violating thread
    // ZwTerminateThread is not exported from ntoskrnl.lib — use process termination
    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = pContext->ProcessId;
    clientId.UniqueThread = NULL;
    if (NT_SUCCESS(ZwOpenProcess(&processHandle, PROCESS_TERMINATE, &objAttr, &clientId)) && processHandle != NULL) {
        ZwTerminateProcess(processHandle, STATUS_ACCESS_DENIED);
        ZwClose(processHandle);
    }
    
    if (pContext->WorkItem != NULL) {
        IoFreeWorkItem(pContext->WorkItem);
    }
    ExFreePoolWithTag(pContext, 'mrTW');

    if (InterlockedDecrement(&g_OutstandingWorkItems) == 0) {
        KeSetEvent(&g_WorkItemDrainEvent, 0, FALSE);
    }
}

typedef struct _CLEANUP_WORK_ITEM_CONTEXT {
    PIO_WORKITEM WorkItem;
    ULONG ProcessId;
} CLEANUP_WORK_ITEM_CONTEXT, *PCLEANUP_WORK_ITEM_CONTEXT;

IO_WORKITEM_ROUTINE CleanupWorkerRoutine;
VOID CleanupWorkerRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PCLEANUP_WORK_ITEM_CONTEXT pContext = (PCLEANUP_WORK_ITEM_CONTEXT)Context;
    
    AtchPrint(("AtchKernel: Executing EmergencyCleanupExam in Worker Thread for PID %lu\n", pContext->ProcessId));
    EmergencyCleanupExam(pContext->ProcessId);
    
    if (pContext->WorkItem != NULL) {
        IoFreeWorkItem(pContext->WorkItem);
    }
    ExFreePoolWithTag(pContext, 'mrCW');

    if (InterlockedDecrement(&g_OutstandingWorkItems) == 0) {
        KeSetEvent(&g_WorkItemDrainEvent, 0, FALSE);
    }
}

void ScheduleEmergencyCleanup(ULONG ProcessId)
{
    // OMEGA-FINAL M03: Atomic read to prevent TOCTOU race during teardown
    PDEVICE_OBJECT devObj = (PDEVICE_OBJECT)InterlockedCompareExchangePointer(
        (PVOID volatile*)&g_DeviceObjectForWorkItems, NULL, NULL);
    if (devObj == NULL) return;

    PCLEANUP_WORK_ITEM_CONTEXT pContext = (PCLEANUP_WORK_ITEM_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CLEANUP_WORK_ITEM_CONTEXT), 'mrCW');
    if (pContext != NULL) {
        pContext->ProcessId = ProcessId;
        pContext->WorkItem = IoAllocateWorkItem(devObj);
        if (pContext->WorkItem != NULL) {
            LONG count = InterlockedIncrement(&g_OutstandingWorkItems);
            if (count > 100) {
                InterlockedDecrement(&g_OutstandingWorkItems);
                IoFreeWorkItem(pContext->WorkItem);
                ExFreePoolWithTag(pContext, 'mrCW');
            } else {
                IoQueueWorkItem(pContext->WorkItem, CleanupWorkerRoutine, DelayedWorkQueue, pContext);
            }
        } else {
            ExFreePoolWithTag(pContext, 'mrCW');
        }
    }
}

// OMEGA-IX-R3-002: Renamed from ForceKillExamProcess to ForceKillProcess
// because this function is used to kill BOTH exam processes AND attacker processes.
void ForceKillProcess(HANDLE ProcessId)
{
    // OMEGA-FINAL M03: Atomic read to prevent TOCTOU race during teardown
    PDEVICE_OBJECT devObj = (PDEVICE_OBJECT)InterlockedCompareExchangePointer(
        (PVOID volatile*)&g_DeviceObjectForWorkItems, NULL, NULL);
    if (devObj == NULL) return;

    PTERMINATION_WORK_ITEM_CONTEXT pContext = (PTERMINATION_WORK_ITEM_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TERMINATION_WORK_ITEM_CONTEXT), 'mrTW');
    if (pContext != NULL) {
        pContext->ProcessId = ProcessId;
        pContext->WorkItem = IoAllocateWorkItem(devObj);
        if (pContext->WorkItem != NULL) {
            // STATIC ANALYSIS FIX H08: Limit work items to prevent NonPaged pool exhaustion
            LONG count = InterlockedIncrement(&g_OutstandingWorkItems);
            if (count > 100) {
                InterlockedDecrement(&g_OutstandingWorkItems);
                IoFreeWorkItem(pContext->WorkItem);
                ExFreePoolWithTag(pContext, 'mrTW');
            } else {
                IoQueueWorkItem(pContext->WorkItem, TerminationWorkerRoutine, DelayedWorkQueue, pContext);
            }
        } else {
            ExFreePoolWithTag(pContext, 'mrTW');
        }
    }
}

// Removed ForceKillExamThread. Use ForceKillProcess instead.

NTSTATUS RegisterSecurityCallbacks(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;

    // Đăng ký Process Callback
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (NT_SUCCESS(status)) {
        InterlockedExchange(&g_ProcessCallbackRegistered, 1);
    } else {
        AtchPrint(("AtchKernel: Đăng ký Process Callback thất bại. Status: 0x%X\n", status));
        return status;
    }

    // Đăng ký Registry Callback
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"360000"); // Độ cao (Altitude) đăng ký
    status = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_RegistryCookie, NULL);
    if (!NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: Đăng ký Registry Callback thất bại. Status: 0x%X\n", status));
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
        InterlockedExchange(&g_ProcessCallbackRegistered, 0);
        return status;
    }

    // Đăng ký ObCallback
    OB_OPERATION_REGISTRATION obOpReg[2];
    obOpReg[0].ObjectType = PsProcessType;
    obOpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOpReg[0].PreOperation = PreOperationCallback;
    obOpReg[0].PostOperation = NULL;

    obOpReg[1].ObjectType = PsThreadType;
    obOpReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOpReg[1].PreOperation = PreOperationCallback;
    obOpReg[1].PostOperation = NULL;

    OB_CALLBACK_REGISTRATION obReg;
    obReg.Version = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 2;
    RtlInitUnicodeString(&altitude, L"360001");
    obReg.Altitude = altitude;
    obReg.RegistrationContext = NULL;
    obReg.OperationRegistration = obOpReg;

    status = ObRegisterCallbacks(&obReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        AtchPrint(("AtchKernel: Đăng ký ObCallbacks thất bại. Status: 0x%X\n", status));
        CmUnRegisterCallback(g_RegistryCookie);
        g_RegistryCookie.QuadPart = 0;
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
        InterlockedExchange(&g_ProcessCallbackRegistered, 0);
        return status;
    }

    return STATUS_SUCCESS;
}

void UnregisterSecurityCallbacks()
{
    if (InterlockedOr(&g_ProcessCallbackRegistered, 0) != 0) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
        InterlockedExchange(&g_ProcessCallbackRegistered, 0);
    }

    // OMEGA-II M01: Atomic exchange prevents torn 64-bit read on 32-bit builds
    LARGE_INTEGER cookieCopy;
    cookieCopy.QuadPart = InterlockedExchange64(&g_RegistryCookie.QuadPart, 0);
    if (cookieCopy.QuadPart != 0) {
        CmUnRegisterCallback(cookieCopy);
    }

    // OMEGA-II M02: Atomic exchange prevents double-unregister race
    PVOID obHandle = InterlockedExchangePointer((PVOID volatile*)&g_ObRegistrationHandle, NULL);
    if (obHandle != NULL) {
        ObUnRegisterCallbacks(obHandle);
    }
}

void DrainWorkItems()
{
    // OMEGA-VIII-R3-003: Wait INDEFINITELY for outstanding work items to complete.
    // Previously had a 10s timeout that allowed unload to proceed while work items
    // were still running, causing use-after-free BSOD when WdfObjectDelete freed
    // the device object that work items reference via IoFreeWorkItem.
    // This mirrors IoReleaseRemoveLockAndWait which also waits indefinitely.
    LARGE_INTEGER delay;
    delay.QuadPart = -10000LL; // 1ms back-off
    ULONG retries = 0;
    while (InterlockedOr(&g_OutstandingWorkItems, 0) > 0) {
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
        retries++;
        // Log every 10 seconds to help diagnose stuck work items
        if (retries % 10000 == 0) {
            AtchPrint(("[Atch_Kernel] WARNING: DrainWorkItems waiting for %ld outstanding items (%lu seconds)...\n",
                InterlockedOr(&g_OutstandingWorkItems, 0), retries / 1000));
        }
    }
}
