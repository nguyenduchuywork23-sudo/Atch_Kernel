#pragma once
#include <ntddk.h>

extern "C" {
    NTSTATUS InitializeInputBlocker();
    void UninitializeInputBlocker();
}
