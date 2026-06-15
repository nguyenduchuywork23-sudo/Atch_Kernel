#pragma once
#include <ntifs.h>
#include "../../include/SharedDef.h"

#ifdef __cplusplus
extern "C" {
#endif

// Khởi tạo Memory Scanner
NTSTATUS InitMemoryScanner();

// Gọi hàm này định kỳ để quét RAM của Exam Process
void CheckMemoryScanner();

#ifdef __cplusplus
}
#endif
