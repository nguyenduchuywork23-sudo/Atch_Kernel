#ifndef THREAD_NOTIFY_H
#define THREAD_NOTIFY_H

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS InitThreadNotify(VOID);
void UnloadThreadNotify(VOID);

#ifdef __cplusplus
}
#endif

#endif // THREAD_NOTIFY_H
