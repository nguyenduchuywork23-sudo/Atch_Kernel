// main.cpp
// [Ring 3 ONLY] Điểm vào của Ứng dụng Giao diện Bài thi (Ring 3 Host).
// - Tạo cửa sổ Win32 Borderless toàn màn hình
// - Khởi tạo WebView2 và load React app
// - Gắn IntegrityChecker, DriverController, HeartbeatManager, MessageBridge
// - Chạy Event Loop chính của ứng dụng
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wrl.h>
#include <WebView2.h>
#include <string>
#include <thread>
#include <atomic>
#include <shlwapi.h>

#include "DriverController.h"
#include "HeartbeatManager.h"
#include "IntegrityChecker.h"
#include "MessageBridge.h"
#include "DynamicScanner.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ─── Hằng số cấu hình ────────────────────────────────────────────────────────
// Session token dùng chung (trong thực tế sẽ được cấp từ server xác thực)
static const wchar_t kSessionToken[] = L"ATCH_SESSION_2026_XYZ";

// URL hoặc đường dẫn nội bộ tới React app
// - DEV  : L"http://localhost:5173"
// - PROD : L"file:///<path_to_dist>/index.html"
static const wchar_t kWebViewUrl[]   = L"http://localhost:5173";

// ─── Trạng thái toàn cục (dùng trong callbacks) ──────────────────────────────
static DriverController  g_driver;
static MessageBridge     g_bridge;
static std::atomic<bool> g_running{ true };
static DynamicScanner*   g_scanner{ nullptr };

// ─── Kiosk Mode Hook ──────────────────────────────────────────────────────────
static HHOOK g_kbdHook = nullptr;

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;
        bool block = false;
        // Chặn phím Windows trái/phải
        if (p->vkCode == VK_LWIN || p->vkCode == VK_RWIN) {
            block = true;
        }
        // Chặn Alt + Tab, Alt + Esc
        if (p->flags & LLKHF_ALTDOWN) {
            if (p->vkCode == VK_TAB || p->vkCode == VK_ESCAPE) {
                block = true;
            }
        }
        // Chặn Ctrl + Esc
        if (p->vkCode == VK_ESCAPE && (GetAsyncKeyState(VK_CONTROL) & 0x8000)) {
            block = true;
        }
        
        if (block) return 1; // Ngăn chặn sự kiện phím
    }
    return CallNextHookEx(g_kbdHook, nCode, wParam, lParam);
}

// ─── Forward declarations ─────────────────────────────────────────────────────
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
void OnKernelViolation(const MONITOR_LOG_ENTRY& entry);
void OnIntegrityFail(const std::wstring& reason);
void OnHeartbeatFail();
void StartEventListenerThread();
void HandleReactMessage(const std::wstring& json);

// ─── Điểm vào ─────────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
    // [SECURITY] Thiết lập DPI-aware để tránh rendering bị scale lạ
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    // [SECURITY] Bật Data Execution Prevention ngay từ đầu
    SetProcessDEPPolicy(PROCESS_DEP_ENABLE);

    // Khởi tạo COM (cần cho WebView2)
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return 1;

    // ─── Bước 1: Kết nối với Kernel Driver ────────────────────────────────────
    bool driverOk = g_driver.Open();
    if (driverOk) {
        // Khởi tạo phiên thi trong Kernel
        g_driver.InitializeExam(
            GetCurrentProcessId(),
            0x01,           // SecurityLevelFlags = Mức bảo mật cơ bản
            kSessionToken);

        // Whitelist chính PID của ứng dụng này
        g_driver.AddWhitelistPid(kSessionToken, GetCurrentProcessId());
    }
    // Nếu driver không kết nối, ứng dụng vẫn chạy nhưng sẽ báo lỗi qua UI

    // ─── Bước 2: Tạo cửa sổ Win32 Borderless ─────────────────────────────────
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = L"AtchKernelHost";
    wc.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    wc.hIcon         = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    // Lấy kích thước toàn màn hình
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    // WS_POPUP | WS_VISIBLE → Cửa sổ không viền, toàn màn hình
    HWND hWnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_NOREDIRECTIONBITMAP,
        L"AtchKernelHost",
        L"Atch Kernel — Secure Exam Browser",
        WS_POPUP | WS_VISIBLE,
        0, 0, screenW, screenH,
        nullptr, nullptr, hInstance, nullptr);

    if (!hWnd) {
        CoUninitialize();
        return 1;
    }

    // [SECURITY] Khóa phím hệ thống (Alt+Tab, WinKey) để làm Kiosk Mode
    g_kbdHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, hInstance, 0);

    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    // ─── Bước 3: Khởi tạo WebView2 (async) ──────────────────────────────────
    CreateCoreWebView2EnvironmentWithOptions(
        nullptr, nullptr, nullptr,
        Microsoft::WRL::Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [hWnd](HRESULT result, ICoreWebView2Environment* env) -> HRESULT
            {
                if (FAILED(result) || !env) return result;

                env->CreateCoreWebView2Controller(
                    hWnd,
                    Microsoft::WRL::Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [hWnd](HRESULT result, ICoreWebView2Controller* ctrl) -> HRESULT
                        {
                            if (FAILED(result) || !ctrl) return result;

                            // Cấu hình kích thước WebView2 phủ toàn cửa sổ
                            RECT bounds{};
                            GetClientRect(hWnd, &bounds);
                            ctrl->put_Bounds(bounds);

                            ICoreWebView2* webview = nullptr;
                            ctrl->get_CoreWebView2(&webview);

                            // [SECURITY] Vô hiệu hóa DevTools, chuột phải trong WebView
                            ICoreWebView2Settings* settings = nullptr;
                            webview->get_Settings(&settings);
                            if (settings) {
                                settings->put_AreDevToolsEnabled(FALSE);
                                settings->put_AreDefaultContextMenusEnabled(FALSE);
                                settings->put_IsStatusBarEnabled(FALSE);
                                settings->put_IsScriptEnabled(TRUE); // Script phải bật
                            }

                            // Gắn MessageBridge, bắt đầu lắng nghe từ React
                            g_bridge.Attach(webview, HandleReactMessage);

                            // Load React App
                            webview->Navigate(kWebViewUrl);

                            // Báo cho React biết driver đã sẵn sàng
                            // (delay nhỏ để React render xong trước)
                            std::thread([webview]() {
                                std::this_thread::sleep_for(std::chrono::seconds(1));
                                // Nếu driver kết nối được → báo READY, nếu không → báo LOST
                                if (g_driver.IsOpen())
                                    g_bridge.NotifyDriverReady();
                                else
                                    g_bridge.NotifyDriverLost();
                            }).detach();

                            return S_OK;
                        })
                    .Get());
                return S_OK;
            })
        .Get());

    // ─── Bước 4: Khởi động các Security Thread ────────────────────────────────

    // Thread 1: IntegrityChecker – tự bảo vệ ứng dụng liên tục
    IntegrityChecker integrityChecker(OnIntegrityFail);
    integrityChecker.Start(3000); // Kiểm tra mỗi 3 giây

    // Thread 2: HeartbeatManager – gửi nhịp tim xuống Kernel mỗi 5 giây
    std::unique_ptr<HeartbeatManager> heartbeat;
    if (driverOk) {
        heartbeat = std::make_unique<HeartbeatManager>(
            g_driver, kSessionToken, OnHeartbeatFail);
        heartbeat->Start(5000);
    }

    // Thread 3: DynamicScanner – Ring-3 First Verification
    // Quét tiến trình mới, kiểm tra chữ ký số, rồi định tuyến quyết định xuống Ring 0.
    DynamicScanner scanner(g_driver, g_bridge, kSessionToken);
    g_scanner = &scanner;
    // Thêm PID của chính ứng dụng vào danh sách tin cậy
    scanner.AddTrustedProcessName(L"AtchKernelHost.exe");
    scanner.Start(4000); // Quét mỗi 4 giây

    // Thread 4: Event Listener – đợi Kernel báo vi phạm (Inverted Call)
    if (driverOk)
        StartEventListenerThread();

    // ─── Bước 5: Message Loop chính của Win32 ────────────────────────────────
    MSG msg{};
    while (g_running.load() && GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // ─── Dọn dẹp ──────────────────────────────────────────────────────────────
    scanner.Stop();
    g_scanner = nullptr;
    if (heartbeat) heartbeat->Stop();
    integrityChecker.Stop();

    if (driverOk) {
        g_driver.TerminateExam(kSessionToken);
        g_driver.Close();
    }

    if (g_kbdHook) UnhookWindowsHookEx(g_kbdHook);
    CoUninitialize();
    return 0;
}

// ─── Window Procedure ─────────────────────────────────────────────────────────
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    // [SECURITY] Chặn Alt+F4, Alt+Tab ở mức cửa sổ Win32
    case WM_SYSCOMMAND:
        if (wParam == SC_CLOSE || wParam == SC_MINIMIZE || wParam == SC_MAXIMIZE)
            return 0; // Chặn, không cho người dùng thu nhỏ/đóng thủ công
        break;

    // Resize WebView2 theo cửa sổ khi thay đổi kích thước
    case WM_SIZE:
        // TODO: Resize webview controller bounds ở đây nếu cần
        break;

    case WM_DESTROY:
        g_running = false;
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ─── Xử lý sự kiện vi phạm từ Kernel ─────────────────────────────────────────
void OnKernelViolation(const MONITOR_LOG_ENTRY& entry)
{
    g_bridge.NotifyViolation(
        entry.ConfiscatedProcessId,
        entry.ImagePath,
        static_cast<ULONG>(entry.Type));
}

// ─── Xử lý vi phạm toàn vẹn Ring 3 ───────────────────────────────────────────
void OnIntegrityFail(const std::wstring& reason)
{
    // Báo cho React UI biết lỗi gì
    g_bridge.NotifyIntegrityFail(reason);
    
    // Tạm thời KHÔNG exit để xem được lỗi trên màn hình đỏ
    if (g_driver.IsOpen())
        g_driver.TerminateExam(kSessionToken);
    // g_running = false;
    // PostQuitMessage(0);
}

// ─── Heartbeat thất bại ────────────────────────────────────────────────────────
void OnHeartbeatFail()
{
    g_bridge.NotifyDriverLost();
    g_running = false;
    PostQuitMessage(0);
}

// ─── Thread lắng nghe sự kiện từ Kernel (Inverted Call) ───────────────────────
void StartEventListenerThread()
{
    std::thread([]() {
        while (g_running.load()) {
            MONITOR_LOG_ENTRY entry{};
            // Blocking call – trả về khi Kernel có sự kiện
            if (g_driver.ListenForEvent(entry)) {
                OnKernelViolation(entry);
            } else {
                // IOCTL thất bại → driver có thể bị unload
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }).detach();
}

// ─── Xử lý message từ React ────────────────────────────────────────────────────
void HandleReactMessage(const std::wstring& json)
{
    // Phân tích JSON đơn giản bằng tìm kiếm chuỗi (có thể thay bằng nlohmann/json)
    if (json.find(L"START_EXAM") != std::wstring::npos) {
        // React yêu cầu bắt đầu bài thi — thao tác đã được khởi tạo ở trên
        // (InitializeExam gọi ngay khi Open() thành công)
    }
    else if (json.find(L"END_EXAM") != std::wstring::npos) {
        if (g_driver.IsOpen())
            g_driver.TerminateExam(kSessionToken);
        g_running = false;
        PostQuitMessage(0);
    }
    else if (json.find(L"REQUEST_UNLOCK") != std::wstring::npos) {
        if (g_driver.IsOpen())
            g_driver.UnlockExam(kSessionToken);
    }
}
