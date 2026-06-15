#include "../inc/MemorySync.h"
#include "../../include/SharedDef.h"

// Sử dụng tag riêng để dễ theo dõi Memory Leak trong WinDbg (Pool Tagging)
#define ATCHK_POOL_TAG 'igiV' 

PVOID SafeAllocatePool(size_t NumberOfBytes)
{
    // ExAllocatePool2 với POOL_FLAG_NON_PAGED mặc định là NX và zero-initialized
    PVOID pMemory = ExAllocatePool2(POOL_FLAG_NON_PAGED, NumberOfBytes, ATCHK_POOL_TAG);
    
    return pMemory;
}

void SafeFreePool(PVOID Ptr)
{
    if (Ptr != NULL) {
        ExFreePoolWithTag(Ptr, ATCHK_POOL_TAG);
    }
}

void InitializeSafeMutex(PFAST_MUTEX Mutex)
{
    if (Mutex != NULL) {
        ExInitializeFastMutex(Mutex);
    }
}

BOOLEAN AcquireSafeMutex(PFAST_MUTEX Mutex)
{
    if (Mutex != NULL) {
        // Fast Mutex chỉ an toàn ở IRQL <= APC_LEVEL
        KIRQL currentIrql = KeGetCurrentIrql();
        if (currentIrql <= APC_LEVEL) {
            ExAcquireFastMutex(Mutex);
            return TRUE;
        } else {
            // Không được phép acquire Fast Mutex ở DISPATCH_LEVEL hoặc cao hơn
            AtchPrint(("AtchKernel: [ERROR] AcquireSafeMutex ở IRQL %u (>= DISPATCH_LEVEL).\n", currentIrql));
            return FALSE;
        }
    }
    return FALSE;
}

void ReleaseSafeMutex(PFAST_MUTEX Mutex)
{
    if (Mutex != NULL) {
        ExReleaseFastMutex(Mutex);
    }
}
