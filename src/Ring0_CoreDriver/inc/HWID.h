#ifndef HWID_H
#define HWID_H

#include <ntddk.h>

// Generates a Hardware ID (HWID) string.
// Caller is responsible for freeing HwidOut->Buffer using ExFreePoolWithTag(..., 'diWH').
NTSTATUS GenerateHWID(PUNICODE_STRING HwidOut);

#endif // HWID_H
