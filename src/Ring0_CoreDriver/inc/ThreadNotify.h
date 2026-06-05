#ifndef THREAD_NOTIFY_H
#define THREAD_NOTIFY_H

#include <ntddk.h>

NTSTATUS InitThreadNotify();
void UnloadThreadNotify();

#endif // THREAD_NOTIFY_H
