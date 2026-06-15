#ifndef ANTIBYOVD_H
#define ANTIBYOVD_H

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN IsVulnerableDriverLoaded(PUNICODE_STRING DriverName);

#ifdef __cplusplus
}
#endif

#endif // ANTIBYOVD_H
