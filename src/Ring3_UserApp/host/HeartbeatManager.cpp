// HeartbeatManager.cpp
// [Ring 3 ONLY] Triển khai vòng lặp Heartbeat.
#include "HeartbeatManager.h"

HeartbeatManager::HeartbeatManager(DriverController& driver,
                                   const std::wstring& sessionToken,
                                   HeartbeatFailCallback onFail)
    : m_driver(driver)
    , m_sessionToken(sessionToken)
    , m_onFail(std::move(onFail))
{
}

HeartbeatManager::~HeartbeatManager()
{
    Stop();
}

void HeartbeatManager::Start(DWORD intervalMs)
{
    m_running   = true;
    m_failCount = 0;
    m_thread    = std::thread([this, intervalMs]() { Run(intervalMs); });
}

void HeartbeatManager::Stop()
{
    m_running = false;
    if (m_thread.joinable())
        m_thread.join();
}

void HeartbeatManager::Run(DWORD intervalMs)
{
    while (m_running.load()) {
        bool ok = m_driver.SendHeartbeat(m_sessionToken.c_str());

        if (ok) {
            m_failCount = 0; // Reset bộ đếm thất bại
        } else {
            ++m_failCount;
            if (m_failCount >= kMaxFailCount) {
                // Driver không phản hồi nhiều lần → báo cáo lỗi nghiêm trọng
                if (m_onFail) m_onFail();
                return; // Thoát vòng lặp
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
    }
}
