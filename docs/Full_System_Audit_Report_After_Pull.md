# Full System Audit Report (After Code Pull)

**Date**: July 25, 2026
**Scope**: Full System (Ring 0 Kernel Driver, Ring 3 C++ Host, React UI, Java Backend)
**Context**: Following the latest code pull, a comprehensive re-audit was performed using parallel subagents across the entire system.

---

## 1. Ring 0 Kernel Driver (Critical Priority)

**Finding 1: Critical IRQL Violation in `EmergencyCleanupExam`**
- **Location**: `src/Ring0_CoreDriver/src/IoctlHandler.cpp` (Line 947)
- **Vulnerability**: `PsLookupProcessByProcessId` (requires `PASSIVE_LEVEL`) is called *after* acquiring a `FastMutex` (which raises IRQL to `APC_LEVEL`).
- **Impact**: Causes immediate BugCheck (Blue Screen of Death / BSOD) `IRQL_NOT_LESS_OR_EQUAL` on modern Windows systems, or deadlocks the system due to `PspCidTable` resource lock contention.

**Finding 2: Inadequate IRQL Guard in `PreOperationCallback`**
- **Location**: `src/Ring0_CoreDriver/src/Callbacks.cpp` (Line 417)
- **Vulnerability**: The IRQL guard `if (KeGetCurrentIrql() >= DISPATCH_LEVEL)` permits execution at `APC_LEVEL`, allowing `PsLookupProcessByProcessId` to be invoked illegally.
- **Impact**: Can lead to unpredictable system crashes/BSODs when process or thread handles are manipulated in an `APC_LEVEL` context.

---

## 2. Ring 3 C++ Host Application

- **Hardcoded Session Token**: A hardcoded session token (`kSessionToken = L"ATCH_SESSION_2026_XYZ"`) is used instead of dynamic tokens from a backend server, which poses a severe security risk.
- **Event Loop & UI Handling Flaws**: `OnIntegrityFail` and `OnHeartbeatFail` call `PostQuitMessage(0)` from background threads instead of the main UI thread, failing to close the exam window during a violation.
- **Thread Cancellation Deadlock**: During shutdown, `ListenForEvent` remains blocked in the kernel while `WinMain` joins the background threads, causing an indefinite freeze.
- **Security Check Bypasses**:
  - PE Header zeroing is commented out in `IntegrityChecker.cpp` (`SecureZeroMemory` is disabled).
  - Weak parent process path validation (only checks filename, not full absolute path).
- **False Positives**:
  - The `CPUID` VM check flags Windows native VBS/Hyper-V as malicious, causing false positive lockouts on modern Windows 11.
  - Naive `RDTSC` timing attacks trigger false positives due to normal OS context switches.
  - System-wide blacklisting of unsigned binaries aggressively blocks benign utilities.
- **Memory/Performance Issues**: 4-minute full process cache clears cause severe CPU/Disk I/O spikes, while the `m_history` vector leaks memory indefinitely.
- **IPC & Webview Security**:
  - Manual, unescaped JSON parsing (`json.find` and `std::stoul`) in `HandleReactMessage` exposes the application to crashing/injection vulnerabilities.
  - Loose domain verification allows `http://attacker-localhost.com` to bypass WebView2 restrictions.
  - Persistent global clipboard clearing every 3 seconds impacts UX.

---

## 3. React Frontend UI

- **Hardcoded Secrets**: Fallback session token `'EXAM_2026_XYZ'` is hardcoded, allowing potential authentication bypass.
- **XSS & Iframe Vulnerabilities**:
  - Unsanitized dynamic `<iframe> src` allows for DOM-based XSS (e.g., `javascript:...` injection).
  - Missing `sandbox` and `referrerPolicy` attributes on the exam iframe.
  - Admin configuration allows saving unvalidated target URLs.
- **IPC / Message Bridge Leaks**:
  - Wildcard target origin message broadcast (`postMessage('*')`).
  - Missing `event.origin` validation allows spoofing host messages (e.g., `VIOLATION_DETECTED`).
  - Console logging of sensitive IPC payloads containing tokens.
- **Token Storage & Security**:
  - Insecure storage of JWT access tokens in `localStorage`.
  - Missing token invalidation (tokens remain after 401/403 responses).
  - Exposed default credentials in UI form hints.
- **Dependencies**: React, Vite, and TypeScript are outdated and require patches.

---

## 4. Java Backend (`ExamBackend`)

- **Authentication & Secrets Management**:
  - **Hardcoded Secrets**: JWT signing key and database root credentials (`123456`) are hardcoded in source/properties.
  - **Unhashed Passwords (NEW)**: `AdminController` saves raw passwords without encoding them via `BCryptPasswordEncoder` when creating users.
  - **Excessive Token Expiration**: JWT tokens last for 10 hours without any revocation or blacklist mechanism.
- **Business Logic Flaws (ExamController)**:
  - **IDOR / Broken Access Control**: Flawed `auth != null` logic bypasses ownership checks, allowing unauthenticated users to submit arbitrary exam sessions.
  - **No State Enforcement**: Submissions can be repeated for already `COMPLETED` exams.
  - **Incomplete Time Constraint**: Only enforces a minimum time (< 1 min) but fails to enforce the maximum duration limit.
  - **Missing Data Validation**: `submissionData` is completely ignored and unpersisted.
- **Hardware ID (HWID) Hijack (High Severity)**:
  - **Auto-binding Hijack**: First login silently sets HWID without authorization verification, allowing an attacker to permanently bind their machine to a student's account.
  - HWID validation is enforced ONLY during login. Submits and other authenticated endpoints do not check HWID, allowing token theft to bypass hardware bindings entirely.
- **Session & CORS Misconfigurations**:
  - **Stateful Session Policy**: Incorrectly uses `SessionCreationPolicy.IF_REQUIRED` alongside stateless JWT filters.
  - **Overly Permissive CORS**: Allowed origins and headers are set to wildcard `*`.
- **Missing Anti-Cheat Endpoint**: `POST /api/security-logs` does not exist, so host client violation logs are silently dropped (404).
- **Insufficient Rate Limiting**: Zero rate limiting on public endpoints (`/api/auth/login`), rendering the system fully vulnerable to brute-force attacks.
- **Dependency Vulnerabilities**: Uses `spring-boot-starter-parent 3.3.1` which is vulnerable to active Path Traversal CVEs (requires `3.3.6+`).
- **Exception Handling**: Swallows generic `Exception`, returns inconsistent error structures, and lacks unified `GlobalExceptionHandler` coverage.

---

**Note:** The system Anti-VM logic in Ring 0 is currently disabled (`TESTING BYPASS` active) to allow for safe testing within Proxmox/KVM environments.
