#ifndef LOAD_IMAGE_NOTIFY_H
#define LOAD_IMAGE_NOTIFY_H

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS InitLoadImageNotify(PDRIVER_OBJECT DriverObject);
void UnloadImageNotify();

#ifdef __cplusplus
}
#endif

#endif // LOAD_IMAGE_NOTIFY_H
