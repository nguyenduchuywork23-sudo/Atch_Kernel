#pragma once
#include <ntddk.h>

extern "C" {
    NTSTATUS RegisterSecurityCallbacks(PDRIVER_OBJECT DriverObject);
    void UnregisterSecurityCallbacks();
}
