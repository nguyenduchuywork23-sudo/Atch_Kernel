#ifndef ANTIVM_H
#define ANTIVM_H

#include <ntddk.h>
#include <intrin.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN DetectHypervisor();

#ifdef __cplusplus
}
#endif

#endif // ANTIVM_H
