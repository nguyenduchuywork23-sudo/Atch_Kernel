#pragma once

#ifndef SHARED_DEF_H
#define SHARED_DEF_H

// [OMEGA-VII] Anti-Reversing: Xóa toàn bộ chuỗi tĩnh khỏi file nhị phân khi Build Release
#ifdef DBG
#define AtchPrint(fmt, ...) KdPrint(("AtchKernel: " fmt, __VA_ARGS__))
#else
#define AtchPrint(fmt, ...)
#endif

// Định nghĩa mã Device Type (Nằm trong dải an toàn cho Custom Drivers từ 32768-65535)
#ifdef __cplusplus
constexpr ULONG ATCH_KERNEL_DEVICE_TYPE = 0x8000;
#else
#define ATCH_KERNEL_DEVICE_TYPE 0x8000
#endif

// Kỹ thuật định nghĩa mã IOCTL chuẩn Microsoft WDK
// OMEGA-FINAL CRIT-02: Changed from FILE_ANY_ACCESS to FILE_WRITE_ACCESS
// to prevent non-admin users (WORLD_R) from sending privileged IOCTLs.
#define IOCTL_AK_INITIALIZE_EXAM \
    CTL_CODE(ATCH_KERNEL_DEVICE_TYPE, 0x900, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_AK_TERMINATE_EXAM \
    CTL_CODE(ATCH_KERNEL_DEVICE_TYPE, 0x901, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_AK_SEND_HEARTBEAT \
    CTL_CODE(ATCH_KERNEL_DEVICE_TYPE, 0x902, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_AK_ADD_WHITELIST_PID \
    CTL_CODE(ATCH_KERNEL_DEVICE_TYPE, 0x903, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// [BỔ SUNG V1.2.0] IOCTL phục vụ cho cơ chế đảo chiều gọi (Inverted Call)
#define IOCTL_AK_LISTEN_EVENT \
    CTL_CODE(ATCH_KERNEL_DEVICE_TYPE, 0x904, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// IOCTL cập nhật danh sách đen linh hoạt (Dynamic Blacklist)
#define IOCTL_AK_UPDATE_BLACKLIST \
    CTL_CODE(ATCH_KERNEL_DEVICE_TYPE, 0x905, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// [BỔ SUNG V1.3.0] IOCTL phục vụ mở khóa ngoại vi khi bị Input Locking
#define IOCTL_AK_UNLOCK_EXAM \
    CTL_CODE(ATCH_KERNEL_DEVICE_TYPE, 0x906, METHOD_BUFFERED, FILE_WRITE_ACCESS)


// Cấu trúc gói tin dữ liệu truyền tải giữa Ring 3 và Ring 0
#pragma pack(push, 8)
typedef struct _EXAM_INIT_DATA {
    ULONG ClientProcessId;      // PID của phần mềm thi cấp User Mode
    ULONG SecurityLevelFlags;   // Các cờ cấu hình mức độ bảo mật chủ động
    WCHAR SessionToken[64];     // Chuỗi khóa bảo mật chống tấn công Replay
} EXAM_INIT_DATA, *PEXAM_INIT_DATA;

// Phân loại vi phạm (Violation Type Enum)
#ifdef __cplusplus
enum class ViolationType : ULONG {
    VIOLATION_REGISTRY_TAMPERING = 1,
    VIOLATION_PROCESS_BLACKLISTED = 2,
    VIOLATION_THREAD_INJECTION = 3,
    VIOLATION_BYOVD_DETECTED = 4,
    VIOLATION_DLL_INJECTION = 5,
    VIOLATION_DKOM_HIDDEN = 6,
    VIOLATION_HEARTBEAT_TIMEOUT = 7,
    VIOLATION_MANUAL_MAPPING = 8
};
#else
typedef enum _ViolationType {
    VIOLATION_REGISTRY_TAMPERING = 1,
    VIOLATION_PROCESS_BLACKLISTED = 2,
    VIOLATION_THREAD_INJECTION = 3,
    VIOLATION_BYOVD_DETECTED = 4,
    VIOLATION_DLL_INJECTION = 5,
    VIOLATION_DKOM_HIDDEN = 6,
    VIOLATION_HEARTBEAT_TIMEOUT = 7,
    VIOLATION_MANUAL_MAPPING = 8
} ViolationType;
#endif

typedef struct _MONITOR_LOG_ENTRY {
    ULONG ConfiscatedProcessId; // PID của tiến trình gian lận bị phát hiện và chặn
    WCHAR ImagePath[256];       // Đường dẫn tệp tin thực thi vi phạm nội quy thi
    ViolationType Type;         // Mức độ/Loại vi phạm
} MONITOR_LOG_ENTRY, *PMONITOR_LOG_ENTRY;

typedef struct _WHITELIST_DATA {
    WCHAR SessionToken[64];
    ULONG Pid;
} WHITELIST_DATA, *PWHITELIST_DATA;

typedef struct _BLACKLIST_DATA {
    WCHAR SessionToken[64];
    ULONG ItemCount;
    // Followed by ItemCount of 256-WCHAR strings.
    // WCHAR Items[ItemCount][256];
} BLACKLIST_DATA, *PBLACKLIST_DATA;
#pragma pack(pop)

#endif // SHARED_DEF_H
