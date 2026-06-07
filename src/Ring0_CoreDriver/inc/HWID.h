#ifndef HWID_H
#define HWID_H

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

// Generates a Hardware ID (HWID) string.
// Caller is responsible for freeing HwidOut->Buffer using ExFreePoolWithTag(..., 'diWH').
NTSTATUS GenerateHWID(PUNICODE_STRING HwidOut);

#ifdef __cplusplus
}
#endif

#endif // HWID_H
