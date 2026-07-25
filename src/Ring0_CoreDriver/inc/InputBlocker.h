#pragma once
#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif
    NTSTATUS InitializeInputBlocker(VOID);
    void UninitializeInputBlocker(VOID);
#ifdef __cplusplus
}
#endif
