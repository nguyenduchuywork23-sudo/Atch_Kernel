#include "../inc/MemorySync.h"

// Sử dụng tag riêng để dễ theo dõi Memory Leak trong WinDbg (Pool Tagging)
#define ATCHK_POOL_TAG 'igiV' 

PVOID SafeAllocatePool(size_t NumberOfBytes)
{
    // Sử dụng NonPagedPoolNx để ngăn ngừa lỗi bảo mật liên quan đến thực thi vùng nhớ dữ liệu
    PVOID pMemory = ExAllocatePoolWithTag(NonPagedPoolNx, NumberOfBytes, ATCHK_POOL_TAG);
    
    if (pMemory != NULL) {
        RtlZeroMemory(pMemory, NumberOfBytes);
    }
    
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
            KdPrint(("AtchKernel: [ERROR] AcquireSafeMutex ở IRQL %u (>= DISPATCH_LEVEL).\n", currentIrql));
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
