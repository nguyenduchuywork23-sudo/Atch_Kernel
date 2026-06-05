#pragma once

#ifndef SHARED_DEF_H
#define SHARED_DEF_H

// Định nghĩa mã Device Type (Nằm trong dải an toàn cho Custom Drivers từ 32768-65535)
#define ATCH_KERNEL_DEVICE_TYPE 0x8000

// Kỹ thuật định nghĩa mã IOCTL chuẩn Microsoft WDK
#define IOCTL_AK_INITIALIZE_EXAM \
    CTL_CODE(ATCH_KERNEL_DEVICE_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_AK_TERMINATE_EXAM \
    CTL_CODE(ATCH_KERNEL_DEVICE_TYPE, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_AK_SEND_HEARTBEAT \
    CTL_CODE(ATCH_KERNEL_DEVICE_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_AK_ADD_WHITELIST_PID \
    CTL_CODE(ATCH_KERNEL_DEVICE_TYPE, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)

// [BỔ SUNG V1.2.0] IOCTL phục vụ cho cơ chế đảo chiều gọi (Inverted Call)
#define IOCTL_AK_LISTEN_EVENT \
    CTL_CODE(ATCH_KERNEL_DEVICE_TYPE, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Cấu trúc gói tin dữ liệu truyền tải giữa Ring 3 và Ring 0
#pragma pack(push, 8)
typedef struct _EXAM_INIT_DATA {
    ULONG ClientProcessId;      // PID của phần mềm thi cấp User Mode
    ULONG SecurityLevelFlags;   // Các cờ cấu hình mức độ bảo mật chủ động
    WCHAR SessionToken[64];     // Chuỗi khóa bảo mật chống tấn công Replay
} EXAM_INIT_DATA, *PEXAM_INIT_DATA;

typedef struct _MONITOR_LOG_ENTRY {
    ULONG ConfiscatedProcessId; // PID của tiến trình gian lận bị phát hiện và chặn
    WCHAR ImagePath[256];       // Đường dẫn tệp tin thực thi vi phạm nội quy thi
    ULONG ViolationType;        // Phân loại lỗi (1: Chặn Registry, 2: Chặn Process, 3: DKOM)
} MONITOR_LOG_ENTRY, *PMONITOR_LOG_ENTRY;
#pragma pack(pop)

#endif // SHARED_DEF_H
