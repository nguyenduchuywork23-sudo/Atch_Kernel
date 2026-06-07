#ifndef THREAD_NOTIFY_H
#define THREAD_NOTIFY_H

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS InitThreadNotify();
void UnloadThreadNotify();

#ifdef __cplusplus
}
#endif

#endif // THREAD_NOTIFY_H
