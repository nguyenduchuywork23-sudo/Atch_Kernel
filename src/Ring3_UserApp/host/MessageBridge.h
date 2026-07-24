// MessageBridge.h
// [Ring 3 ONLY] Giao tiếp JSON hai chiều giữa C++ Host và React (WebView2).
// - C++ → React : PostWebMessageAsJson()
// - React → C++ : add_WebMessageReceived event handler
#pragma once
#ifndef MESSAGE_BRIDGE_H
#define MESSAGE_BRIDGE_H

#include <windows.h>
#include <wrl.h>
#include <string>
#include <functional>

// Forward declarations (tránh kéo toàn bộ WebView2 headers vào đây)
struct ICoreWebView2;
struct ICoreWebView2Controller;

#define WM_POST_TO_REACT (WM_APP + 1)

// Callback khi nhận được JSON từ React gửi sang
using BridgeMessageCallback = std::function<void(const std::wstring& jsonMessage)>;

class MessageBridge {
public:
    MessageBridge() = default;

    // Cài đặt WebView2 controller để có thể gửi/nhận message
    void Attach(HWND hwnd, ICoreWebView2* webview, BridgeMessageCallback onMessage);

    // Gửi JSON từ C++ → React (Thread-safe)
    void PostToReact(const std::wstring& jsonPayload);

    // Thực thi gọi WebView2 trực tiếp (phải gọi trên UI Thread)
    void ExecutePostToReact(const std::wstring& jsonPayload);

    // ── Các hàm helper tạo sẵn JSON payload thông dụng ──────────────────────
    // Gửi thông báo driver đã kết nối
    void NotifyDriverReady();
    // Gửi thông báo vi phạm phát hiện từ Kernel
    void NotifyViolation(ULONG pid, const std::wstring& imagePath,
                         ULONG violationType);
    // Gửi thông báo driver mất kết nối (Heartbeat fail)
    void NotifyDriverLost();
    // Gửi thông báo vi phạm toàn vẹn Ring 3
    void NotifyIntegrityFail(const std::wstring& reason);
    void NotifySystemStats(int cpuUsage, int ramUsage, int processCount);

private:
    HWND m_hwnd{ nullptr };
    Microsoft::WRL::ComPtr<ICoreWebView2> m_webview;
};

#endif // MESSAGE_BRIDGE_H
