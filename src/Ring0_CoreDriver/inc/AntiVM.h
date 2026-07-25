#ifndef _ANTI_VM_H_
#define _ANTI_VM_H_

#include <ntifs.h>
#include <intrin.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN DetectHypervisor(VOID);
BOOLEAN IsHypervisorDetected(VOID);
BOOLEAN CheckMsrLstarIntegrity(VOID); // OMEGA-XXV: Periodic MSR_LSTAR tamper check

#ifdef __cplusplus
}
#endif

#endif // _ANTI_VM_H_
