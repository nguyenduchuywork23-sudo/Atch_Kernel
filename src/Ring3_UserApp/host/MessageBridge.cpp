// MessageBridge.cpp
// [Ring 3 ONLY] Triển khai JSON bridge C++ <-> React.
#include "MessageBridge.h"
#include <WebView2.h>    // WebView2 SDK header (cần cài qua NuGet/CMake)
#include <sstream>

void MessageBridge::Attach(ICoreWebView2* webview, BridgeMessageCallback onMessage)
{
    m_webview = webview;
    if (!m_webview) return;

    // Đăng ký lắng nghe message từ React (window.chrome.webview.postMessage)
    m_webview->add_WebMessageReceived(
        Microsoft::WRL::Callback<ICoreWebView2WebMessageReceivedEventHandler>(
            [cb = std::move(onMessage)](
                ICoreWebView2* /*sender*/,
                ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT
            {
                LPWSTR rawJson = nullptr;
                args->get_WebMessageAsJson(&rawJson);
                if (rawJson && cb)
                    cb(std::wstring(rawJson));
                CoTaskMemFree(rawJson);
                return S_OK;
            })
        .Get(), nullptr);
}

void MessageBridge::PostToReact(const std::wstring& jsonPayload)
{
    if (m_webview)
        m_webview->PostWebMessageAsJson(jsonPayload.c_str());
}

// ── Helper builders ─────────────────────────────────────────────────────────
void MessageBridge::NotifyDriverReady()
{
    PostToReact(L"{\"type\":\"DRIVER_INITIALIZED\",\"payload\":{\"success\":true}}");
}

void MessageBridge::NotifyViolation(ULONG pid,
                                    const std::wstring& imagePath,
                                    ULONG violationType)
{
    std::wostringstream ss;
    ss << L"{\"type\":\"VIOLATION_DETECTED\","
       << L"\"payload\":{"
       << L"\"pid\":"          << pid          << L","
       << L"\"violationType\":" << violationType << L","
       << L"\"processName\":\"" << imagePath    << L"\""
       << L"}}";
    PostToReact(ss.str());
}

void MessageBridge::NotifyDriverLost()
{
    PostToReact(L"{\"type\":\"DRIVER_LOST\",\"payload\":{}}");
}

void MessageBridge::NotifyIntegrityFail(const std::wstring& reason)
{
    std::wostringstream ss;
    ss << L"{\"type\":\"INTEGRITY_FAIL\","
       << L"\"payload\":{\"reason\":\"" << reason << L"\"}}";
    PostToReact(ss.str());
}
