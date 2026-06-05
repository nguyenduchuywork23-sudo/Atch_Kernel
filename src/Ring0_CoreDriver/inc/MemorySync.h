#pragma once
#include <ntddk.h>

extern "C" {
    // Cấp phát bộ nhớ an toàn (NonPagedPoolNx)
    PVOID SafeAllocatePool(size_t NumberOfBytes);
    void SafeFreePool(PVOID Ptr);

    // Đồng bộ hóa với Fast Mutex
    void InitializeSafeMutex(PFAST_MUTEX Mutex);
    void AcquireSafeMutex(PFAST_MUTEX Mutex);
    void ReleaseSafeMutex(PFAST_MUTEX Mutex);
}
