#pragma once
#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif
    // Cấp phát bộ nhớ an toàn (NonPagedPoolNx)
    PVOID SafeAllocatePool(size_t NumberOfBytes);
    void SafeFreePool(PVOID Ptr);

    // Đồng bộ hóa với Fast Mutex
    void InitializeSafeMutex(PFAST_MUTEX Mutex);
    BOOLEAN AcquireSafeMutex(PFAST_MUTEX Mutex);
    void ReleaseSafeMutex(PFAST_MUTEX Mutex);
#ifdef __cplusplus
}
#endif
