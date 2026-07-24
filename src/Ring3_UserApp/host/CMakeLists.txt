cmake_minimum_required(VERSION 3.24)
project(AtchKernelHost VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Nguồn C++ Host ────────────────────────────────────────────────────────────
set(HOST_SOURCES
    main.cpp
    DriverController.cpp
    HeartbeatManager.cpp
    IntegrityChecker.cpp
    MessageBridge.cpp
    DynamicScanner.cpp
    Logger.cpp
)

# ── Tạo file thực thi Windows GUI (không có console đen) ─────────────────────
add_executable(AtchKernelHost WIN32 ${HOST_SOURCES})



# ── Include: SharedDef.h (dùng chung với Ring 0, KHÔNG SỬA file này) ─────────
target_include_directories(AtchKernelHost PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include   # → include/SharedDef.h
)

# ── Tìm WebView2 SDK ─────────────────────────────────────────────────────────
# Ưu tiên: Biến CMake WEBVIEW2_DIR hoặc env WEBVIEW2_SDK_DIR
# Cài đặt: Tải NuGet package 'Microsoft.Web.WebView2' rồi trỏ đường dẫn vào đây
if(DEFINED WEBVIEW2_DIR)
    # Được truyền từ command line
elseif(DEFINED ENV{WEBVIEW2_SDK_DIR})
    set(WEBVIEW2_DIR "$ENV{WEBVIEW2_SDK_DIR}")
else()
    # Fallback: tìm trong thư mục packages NuGet phổ biến
    set(WEBVIEW2_DIR "${CMAKE_SOURCE_DIR}/../packages/Microsoft.Web.WebView2/build/native")
endif()

set(WEBVIEW2_INC "${WEBVIEW2_DIR}/include")
set(WEBVIEW2_LIB "${WEBVIEW2_DIR}/x64/WebView2LoaderStatic.lib")

if(EXISTS "${WEBVIEW2_INC}/WebView2.h")
    message(STATUS "WebView2 SDK found at: ${WEBVIEW2_DIR}")
    target_include_directories(AtchKernelHost PRIVATE "${WEBVIEW2_INC}")
    target_link_libraries(AtchKernelHost PRIVATE "${WEBVIEW2_LIB}")
    target_compile_definitions(AtchKernelHost PRIVATE USE_WEBVIEW2_STATIC)
    add_custom_command(TARGET AtchKernelHost POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WEBVIEW2_DIR}/x64/WebView2Loader.dll"
        $<TARGET_FILE_DIR:AtchKernelHost>
    )
else()
    message(WARNING
        "WebView2 SDK not found at '${WEBVIEW2_INC}'.\n"
        "Install via NuGet: Install-Package Microsoft.Web.WebView2\n"
        "Then set -DWEBVIEW2_DIR=<path> or env WEBVIEW2_SDK_DIR.")
endif()

# ── Windows Compile Options ───────────────────────────────────────────────────
if(MSVC)
    target_compile_definitions(AtchKernelHost PRIVATE UNICODE _UNICODE)
    target_compile_options(AtchKernelHost PRIVATE
        "/W4"               # Warning level 4
        "/WX"               # Treat warnings as errors
    )
    target_link_options(AtchKernelHost PRIVATE
        /NXCOMPAT           # Data Execution Prevention
        /DYNAMICBASE        # ASLR
        /SUBSYSTEM:WINDOWS  # GUI App
    )
endif()

# ── Windows SDK Libraries ─────────────────────────────────────────────────────
target_link_libraries(AtchKernelHost PRIVATE
    user32
    gdi32
    ole32
    oleaut32
    shlwapi
    psapi
    ntdll
    shell32
    wintrust    # WinVerifyTrust — Chữ ký số
    crypt32     # CryptoAPI — SHA-256
)
