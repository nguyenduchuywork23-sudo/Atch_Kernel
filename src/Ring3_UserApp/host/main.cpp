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
#include <WebView2EnvironmentOptions.h>

#include "DriverController.h"
#include "HeartbeatManager.h"
#include "IntegrityChecker.h"
#include "MessageBridge.h"
#include "DynamicScanner.h"
#include "Logger.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Session token dùng chung (trong thực tế sẽ được cấp từ server xác thực)
static std::wstring g_sessionToken;

// URL hoặc đường dẫn nội bộ tới React app
// - DEV  : L"http://localhost:5173"
// - PROD : L"file:///<path_to_dist>/index.html"
static const wchar_t kWebViewUrl[]   = L"http://localhost:5173";

// ─── Trạng thái toàn cục (dùng trong callbacks) ──────────────────────────────
static DriverController  g_driver;
static MessageBridge     g_bridge;
static std::atomic<bool> g_running{ true };
static DynamicScanner*   g_scanner{ nullptr };
static Microsoft::WRL::ComPtr<ICoreWebView2Controller> g_webviewController;
static HWND g_hWnd = nullptr;

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
        // Chặn Alt + Tab, Alt + Esc, Alt + F4
        if (p->flags & LLKHF_ALTDOWN) {
            if (p->vkCode == VK_TAB || p->vkCode == VK_ESCAPE || p->vkCode == VK_F4) {
                block = true;
            }
        }
        // Chặn Ctrl + Esc
        if (p->vkCode == VK_ESCAPE && (GetAsyncKeyState(VK_CONTROL) & 0x8000)) {
            block = true;
        }
        
        // [DEV ONLY] Đóng backdoor Ctrl+Q
        // if (p->vkCode == 'Q' && (GetAsyncKeyState(VK_CONTROL) & 0x8000)) {
        //     PostQuitMessage(0);
        // }

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
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

#include <stdio.h>
#include <vector>

std::vector<std::thread> g_bgThreads;

int main() {
    printf("Main started!\n");
    return WinMain(GetModuleHandle(NULL), NULL, GetCommandLineA(), SW_SHOW);
}
// ─── Điểm vào ─────────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
    // Lấy session token từ tham số dòng lệnh
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv && argc > 1) {
        g_sessionToken = argv[1];
    } else {
        LOG_ERR("No session token provided. Exiting.");
        if (argv) LocalFree(argv);
        return 1;
    }
    if (argv) LocalFree(argv);

    // [SECURITY] Thiết lập DPI-aware để tránh rendering bị scale lạ
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    // [SECURITY] Bật Data Execution Prevention ngay từ đầu
    SetProcessDEPPolicy(PROCESS_DEP_ENABLE);

    // Khởi tạo COM (cần cho WebView2)
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return 1;

    // Khởi tạo Logger
    Logger::GetInstance().Init(L"AtchKernelHost.log");
    LOG_INFO("AtchKernelHost is starting...");
    // ─── Bước 1: Kết nối với Kernel Driver ────────────────────────────────────
    bool driverOk = g_driver.Open();
    if (driverOk) {
        LOG_INFO("Connected to Atch Kernel Driver successfully.");
        g_driver.InitializeExam(GetCurrentProcessId(), 0x01, g_sessionToken.c_str());
        g_driver.AddWhitelistPid(g_sessionToken.c_str(), GetCurrentProcessId());
        LOG_INFO("Exam session initialized in Kernel.");
    } else {
        LOG_WARN("Failed to connect to Atch Kernel Driver. Operating in UI-only mode.");
    }
    
    LOG_INFO("Reaching Step 2...");
    
    // ─── Tạo Môi trường Cách ly (Secure Desktop) ──────────────────────────────
    HDESK hSecureDesktop = CreateDesktopW(L"AtchSecureDesktop", NULL, NULL, 0, GENERIC_ALL, NULL);
    if (hSecureDesktop) {
        SwitchDesktop(hSecureDesktop);
        SetThreadDesktop(hSecureDesktop);
        LOG_INFO("Switched to Secure Desktop.");
    } else {
        LOG_WARN("Failed to create Secure Desktop.");
    }

    // ─── Bước 2: Tạo cửa sổ Win32 Borderless ─────────────────────────────────
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = L"AtchKernelHost";
    wc.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    wc.hIcon         = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    
    LOG_INFO("Registering class...");
    RegisterClassExW(&wc);

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    LOG_INFO("Calling CreateWindowExW...");
    HWND hWnd = CreateWindowExW(
        WS_EX_TOPMOST,
        L"AtchKernelHost",
        L"Atch Kernel — Secure Exam Browser",
        WS_POPUP | WS_VISIBLE,
        0, 0, screenW, screenH,
        nullptr, nullptr, hInstance, nullptr);

    if (!hWnd) {
        LOG_ERR("CreateWindowExW failed. Error: " + std::to_string(GetLastError()));
        CoUninitialize();
        return 1;
    }
    g_hWnd = hWnd;
    SetWindowDisplayAffinity(g_hWnd, WDA_MONITOR);

    LOG_INFO("Setting Keyboard Hook...");
    // [SECURITY] Khóa phím hệ thống (Alt+Tab, WinKey) để làm Kiosk Mode
    g_kbdHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, hInstance, 0);

    LOG_INFO("Calling ShowWindow...");
    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    LOG_INFO("Reaching Step 3 (WebView2)...");
    // ─── Bước 3: Khởi tạo WebView2 (async) ──────────────────────────────────
    auto options = Microsoft::WRL::Make<CoreWebView2EnvironmentOptions>();
    options->put_AdditionalBrowserArguments(L"");

    CreateCoreWebView2EnvironmentWithOptions(
        nullptr, nullptr, options.Get(),
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

                            g_webviewController = ctrl;

                            // Cấu hình kích thước WebView2 phủ toàn cửa sổ
                            RECT bounds{};
                            GetClientRect(hWnd, &bounds);
                            ctrl->put_Bounds(bounds);

                            Microsoft::WRL::ComPtr<ICoreWebView2> webview;
                            ctrl->get_CoreWebView2(&webview);

                            // [SECURITY] Vô hiệu hóa DevTools, chuột phải trong WebView
                            ICoreWebView2Settings* settings = nullptr;
                            webview->get_Settings(&settings);
                            if (settings) {
                                settings->put_AreDevToolsEnabled(FALSE);
                                settings->put_AreDefaultContextMenusEnabled(FALSE);
                                settings->put_IsStatusBarEnabled(FALSE);
                                settings->put_IsScriptEnabled(TRUE); // Script phải bật
                                settings->Release(); // Release the raw COM pointer properly
                            }

                            // [SECURITY] Chặn toàn bộ điều hướng (Navigation) tới các domain không được phép
                            webview->add_NavigationStarting(
                                Microsoft::WRL::Callback<ICoreWebView2NavigationStartingEventHandler>(
                                    [](ICoreWebView2* sender, ICoreWebView2NavigationStartingEventArgs* args) -> HRESULT {
                                        (void)sender;
                                        LPWSTR uri = nullptr;
                                        if (SUCCEEDED(args->get_Uri(&uri)) && uri) {
                                            std::wstring wUri = uri;
                                            // Chỉ cho phép localhost (React App) và itest.cmcu.edu.vn (Bài thi)
                                            if (wUri.find(L"http://localhost:5173/") != 0 && wUri != L"http://localhost:5173" &&
                                                wUri.find(L"https://itest.cmcu.edu.vn/") != 0 && wUri != L"https://itest.cmcu.edu.vn") {
                                                args->put_Cancel(TRUE); // Chặn điều hướng
                                                LOG_WARN(L"Blocked unauthorized navigation to: " + wUri);
                                            }
                                            CoTaskMemFree(uri);
                                        }
                                        return S_OK;
                                    }).Get(), nullptr);

                            // [SECURITY] Chặn hoàn toàn việc mở cửa sổ mới (Popup, _blank links)
                            webview->add_NewWindowRequested(
                                Microsoft::WRL::Callback<ICoreWebView2NewWindowRequestedEventHandler>(
                                    [](ICoreWebView2* sender, ICoreWebView2NewWindowRequestedEventArgs* args) -> HRESULT {
                                        (void)sender;
                                        args->put_Handled(TRUE); // Hủy thao tác mở cửa sổ
                                        LOG_WARN("Blocked popup/new window request.");
                                        return S_OK;
                                    }).Get(), nullptr);

                            // Gắn MessageBridge, bắt đầu lắng nghe từ React
                            g_bridge.Attach(hWnd, webview.Get(), HandleReactMessage);

                            // Load React App
                            LOG_INFO("Loading WebView2 URL...");
                            webview->Navigate(kWebViewUrl);

                            // Báo cho React biết driver đã sẵn sàng
                            // (delay nhỏ để React render xong trước)
                            g_bgThreads.emplace_back([]() {
                                std::this_thread::sleep_for(std::chrono::seconds(1));
                                // Nếu driver kết nối được → báo READY, nếu không → báo LOST
                                if (g_driver.IsOpen())
                                    g_bridge.NotifyDriverReady();
                                else
                                    g_bridge.NotifyDriverLost();
                            });

                            return S_OK;
                        })
                    .Get());
                return S_OK;
            })
        .Get());

    LOG_INFO("Reaching Step 4 (Security Threads)...");
    // ─── Bước 4: Khởi động các Security Thread ────────────────────────────────

    // Thread 1: IntegrityChecker – tự bảo vệ ứng dụng liên tục
    IntegrityChecker integrityChecker(OnIntegrityFail);
    integrityChecker.Start(3000); // Kiểm tra mỗi 3 giây

    // Thread 2: HeartbeatManager – gửi nhịp tim xuống Kernel mỗi 1 giây
    std::unique_ptr<HeartbeatManager> heartbeat;
    if (driverOk) {
        heartbeat = std::make_unique<HeartbeatManager>(
            g_driver, g_sessionToken, OnHeartbeatFail);
        heartbeat->Start(1000);
    }

    // Thread 3: DynamicScanner – Ring-3 First Verification
    // Quét tiến trình mới, kiểm tra chữ ký số, rồi định tuyến quyết định xuống Ring 0.
    DynamicScanner scanner(g_driver, g_bridge, g_sessionToken);
    g_scanner = &scanner;
    // Thêm PID của chính ứng dụng vào danh sách tin cậy
    scanner.AddTrustedProcessName(L"AtchKernelHost.exe");
    scanner.Start(4000); // Quét mỗi 4 giây

    // Thread 4: Event Listener – đợi Kernel báo vi phạm (Inverted Call)
    if (driverOk)
        StartEventListenerThread();

    // Thread 5: Telemetry stats
    g_bgThreads.emplace_back([]() {
        while (g_running.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            // Simulate reading system stats
            int fakeCpu = rand() % 30 + 10;
            int fakeRam = 2048 + (rand() % 512);
            int fakeProcs = 140 + (rand() % 10);
            g_bridge.NotifySystemStats(fakeCpu, fakeRam, fakeProcs);
        }
    });

    // ─── Bước 5: Message Loop chính của Win32 ────────────────────────────────
    MSG msg{};
    BOOL bRet = 0;
    LOG_INFO("Entering message loop...");
    while (g_running.load() && (bRet = GetMessageW(&msg, nullptr, 0, 0)) != 0) {
        if (bRet == -1) {
            LOG_ERR("GetMessageW returned -1!");
            break;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    LOG_INFO("Message loop exited. bRet=" + std::to_string(bRet) + ", g_running=" + std::to_string((int)g_running.load()));

    // ─── Dọn dẹp ──────────────────────────────────────────────────────────────
    LOG_INFO("Shutting down AtchKernelHost...");
    scanner.Stop();
    g_scanner = nullptr;
    if (heartbeat) heartbeat->Stop();
    integrityChecker.Stop();

    if (driverOk) {
        g_driver.CancelPendingIo();
        g_driver.TerminateExam(g_sessionToken.c_str());
        g_driver.Close();
        LOG_INFO("Terminated exam session and closed driver.");
    }

    if (g_kbdHook) UnhookWindowsHookEx(g_kbdHook);
    CoUninitialize();

    // Dọn dẹp các thread nền
    for (auto& t : g_bgThreads) {
        if (t.joinable()) {
            t.join();
        }
    }

    // Phục hồi desktop
    if (hSecureDesktop) {
        HDESK hDefault = OpenDesktopW(L"default", 0, FALSE, GENERIC_ALL);
        if (hDefault) {
            SwitchDesktop(hDefault);
            SetThreadDesktop(hDefault);
            CloseDesktop(hDefault);
        }
        CloseDesktop(hSecureDesktop);
    }

    LOG_INFO("Shutdown complete.");
    return 0;
}

// ─── Window Procedure ─────────────────────────────────────────────────────────
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    // Cảnh báo: Log quá nhiều có thể gây chậm, nhưng cần để debug
    if (msg == WM_CREATE) LOG_INFO("WndProc: WM_CREATE");
    if (msg == WM_NCCREATE) LOG_INFO("WndProc: WM_NCCREATE");
    if (msg == WM_SIZE) LOG_INFO("WndProc: WM_SIZE");

    switch (msg) {
    // [SECURITY] Chặn Alt+F4, Alt+Tab ở mức cửa sổ Win32
    case WM_SYSCOMMAND:
        if (wParam == SC_CLOSE || wParam == SC_MINIMIZE || wParam == SC_MAXIMIZE)
            return 0; // Chặn, không cho người dùng thu nhỏ/đóng thủ công
        break;

    // Resize WebView2 theo cửa sổ khi thay đổi kích thước
    case WM_SIZE:
        if (g_webviewController) {
            RECT bounds{};
            GetClientRect(hWnd, &bounds);
            g_webviewController->put_Bounds(bounds);
        }
        break;

    case WM_POST_TO_REACT: {
        auto* payload = reinterpret_cast<std::wstring*>(lParam);
        if (payload) {
            g_bridge.ExecutePostToReact(*payload);
            delete payload;
        }
        return 0;
    }

    case WM_CLOSE:
        LOG_INFO("WndProc: WM_CLOSE received");
        break;

    case WM_DESTROY:
        LOG_INFO("WndProc: WM_DESTROY received");
        g_running = false;
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ─── Xử lý sự kiện vi phạm từ Kernel ─────────────────────────────────────────
void OnKernelViolation(const MONITOR_LOG_ENTRY& entry)
{
    LOG_WARN("Received violation from Kernel Driver.");
    g_bridge.NotifyViolation(
        entry.ConfiscatedProcessId,
        entry.ImagePath,
        static_cast<ULONG>(entry.Type));
}

// ─── Xử lý vi phạm toàn vẹn Ring 3 ───────────────────────────────────────────
void OnIntegrityFail(const std::wstring& reason)
{
    LOG_ERR(L"Integrity Checker Failed: " + reason);
    // Báo cho React UI biết lỗi gì
    g_bridge.NotifyIntegrityFail(reason);
    
    // Bắt buộc exit để ngăn gian lận
    if (g_driver.IsOpen())
        g_driver.TerminateExam(g_sessionToken.c_str());
    g_running = false;
    if (g_hWnd) PostMessageW(g_hWnd, WM_CLOSE, 0, 0);
}

// ─── Heartbeat thất bại ────────────────────────────────────────────────────────
void OnHeartbeatFail()
{
    LOG_ERR("Heartbeat Manager reported failure (driver lost).");
    g_bridge.NotifyDriverLost();
    g_running = false;
    if (g_hWnd) PostMessageW(g_hWnd, WM_CLOSE, 0, 0);
}

// ─── Thread lắng nghe sự kiện từ Kernel (Inverted Call) ───────────────────────
void StartEventListenerThread()
{
    g_bgThreads.emplace_back([]() {
        while (g_running.load()) {
            MONITOR_LOG_ENTRY entry{};
            // Blocking call – trả về khi Kernel có sự kiện
            if (g_driver.ListenForEvent(g_sessionToken.c_str(), entry)) {
                OnKernelViolation(entry);
            } else {
                // IOCTL thất bại → driver có thể bị unload
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    });
}

#include <regex>

// ─── Xử lý message từ React ────────────────────────────────────────────────────
void HandleReactMessage(const std::wstring& json)
{
    if (json.find(L"START_EXAM") != std::wstring::npos) {
        // React yêu cầu bắt đầu bài thi — thao tác đã được khởi tạo ở trên
    }
    else if (json.find(L"END_EXAM") != std::wstring::npos) {
        if (g_driver.IsOpen())
            g_driver.TerminateExam(g_sessionToken.c_str());
        g_running = false;
        if (g_hWnd) PostMessageW(g_hWnd, WM_CLOSE, 0, 0);
    }
    else if (json.find(L"REQUEST_UNLOCK") != std::wstring::npos) {
        if (g_driver.IsOpen())
            g_driver.UnlockExam(g_sessionToken.c_str());
    }
    else if (json.find(L"HEARTBEAT") != std::wstring::npos) {
        if (g_driver.IsOpen()) {
            g_driver.SendHeartbeat(g_sessionToken.c_str());
            LOG_DEBUG("Forwarded HEARTBEAT to Kernel");
        }
    }
    else if (json.find(L"KILL_PROCESS") != std::wstring::npos) {
        size_t pos = json.find(L"\"pid\"");
        if (pos != std::wstring::npos) {
            size_t colon = json.find(L":", pos);
            if (colon != std::wstring::npos) {
                size_t start = json.find_first_of(L"0123456789", colon);
                size_t end = json.find_first_not_of(L"0123456789", start);
                if (start != std::wstring::npos) {
                    std::wstring pidStr = json.substr(start, end - start);
                    try {
                        DWORD pid = std::stoul(pidStr);
                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                        if (hProc) {
                            TerminateProcess(hProc, 1);
                            CloseHandle(hProc);
                            LOG_INFO("Killed process " + std::to_string(pid) + " via React request.");
                        }
                    } catch (...) {
                        LOG_ERR("Invalid PID format from React UI.");
                    }
                }
            }
        }
    }
}

