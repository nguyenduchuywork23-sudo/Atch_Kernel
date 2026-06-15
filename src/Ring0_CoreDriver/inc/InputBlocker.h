#pragma once
#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif
    NTSTATUS InitializeInputBlocker();
    void UninitializeInputBlocker();
#ifdef __cplusplus
}
#endif
