// HeartbeatManager.h
// [Ring 3 ONLY] Quản lý vòng lặp gửi Heartbeat định kỳ xuống Kernel.
// Nếu thread này dừng (ví dụ: UI bị kill), Kernel sẽ phát hiện sau khoảng
// kTimeoutMs và báo VIOLATION_HEARTBEAT_TIMEOUT.
#pragma once
#ifndef HEARTBEAT_MANAGER_H
#define HEARTBEAT_MANAGER_H

#include <atomic>
#include <thread>
#include <string>
#include <functional>
#include "DriverController.h"

// Callback khi Heartbeat liên tục thất bại (driver không phản hồi)
using HeartbeatFailCallback = std::function<void()>;

class HeartbeatManager {
public:
    HeartbeatManager(DriverController& driver,
                     const std::wstring& sessionToken,
                     HeartbeatFailCallback onFail);
    ~HeartbeatManager();

    void Start(DWORD intervalMs = 5000);
    void Stop();

private:
    void Run(DWORD intervalMs);

    DriverController&    m_driver;
    std::wstring         m_sessionToken;
    HeartbeatFailCallback m_onFail;
    std::atomic<bool>    m_running{ false };
    std::thread          m_thread;
    int                  m_failCount{ 0 };
    static constexpr int kMaxFailCount = 3; // Ngừng sau 3 lần thất bại liên tiếp
};

#endif // HEARTBEAT_MANAGER_H
