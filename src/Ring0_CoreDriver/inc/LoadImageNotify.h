#ifndef LOAD_IMAGE_NOTIFY_H
#define LOAD_IMAGE_NOTIFY_H

#include <ntddk.h>

NTSTATUS InitLoadImageNotify(PDRIVER_OBJECT DriverObject);
void UnloadImageNotify();

#endif // LOAD_IMAGE_NOTIFY_H
