cmake_minimum_required(VERSION 3.24)
project(Atch_Kernel VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── WDK SDK paths ─────────────────────────────────────────────────────────────
# Resolve the Windows Kit root and version from environment variables.
# Falls back to the most common default if the env vars are not set.
if(DEFINED ENV{WindowsSdkDir})
    set(WDK_ROOT "$ENV{WindowsSdkDir}")
else()
    set(WDK_ROOT "C:/Program Files (x86)/Windows Kits/10")
endif()

if(DEFINED ENV{WindowsSDKVersion})
    # The env var sometimes has a trailing backslash – strip it.
    string(REGEX REPLACE "[/\\\\]+$" "" WDK_VERSION "$ENV{WindowsSDKVersion}")
else()
    set(WDK_VERSION "10.0.22621.0")
endif()

set(WDK_INC_ROOT "${WDK_ROOT}/Include/${WDK_VERSION}")
set(WDK_LIB_ROOT "${WDK_ROOT}/Lib/${WDK_VERSION}")

# ── Driver source files ───────────────────────────────────────────────────────
file(GLOB_RECURSE DRIVER_SOURCES CONFIGURE_DEPENDS
    "src/Ring0_CoreDriver/src/*.cpp"
    "src/Ring0_CoreDriver/src/*.c"
)

# ── Driver target ─────────────────────────────────────────────────────────────
# Create an executable target but change suffix to .sys for Windows Kernel Mode Driver
add_executable(Ring0_CoreDriver ${DRIVER_SOURCES})
set_target_properties(Ring0_CoreDriver PROPERTIES SUFFIX ".sys")

# ── Per-target include directories (replaces old include_directories()) ───────
target_include_directories(Ring0_CoreDriver PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Ring0_CoreDriver/inc
)

if(MSVC)
    # ── WDK include directories ───────────────────────────────────────────────
    target_include_directories(Ring0_CoreDriver PRIVATE
        "${WDK_INC_ROOT}/km"
        "${WDK_INC_ROOT}/km/crt"
        "${WDK_INC_ROOT}/shared"
    )

    # ── Compile options for kernel mode driver ────────────────────────────────
    target_compile_options(Ring0_CoreDriver PRIVATE
        "/kernel"              # Create kernel mode executable
        "/GR-"                 # Disable RTTI
        "/EHs-c-"              # Disable C++ exceptions
        "/Zc:threadSafeInit-"  # Disable thread-safe statics
        "/W4"                  # Warning level 4
        "/WX"                  # Treat warnings as errors
    )

    # ── Link options for kernel mode driver (modern target_link_options) ──────
    target_link_options(Ring0_CoreDriver PRIVATE
        /DRIVER
        /ENTRY:DriverEntry
        /NODEFAULTLIB
        /SUBSYSTEM:NATIVE
        /OPT:REF
        /OPT:ICF
        /MANIFEST:NO
    )

    # ── WDK kernel libraries ─────────────────────────────────────────────────
    set(WDK_KMLIB_DIR "${WDK_LIB_ROOT}/km/x64")

    foreach(_lib ntoskrnl hal wdmsec BufferOverflowFastFailK)
        find_library(WDK_${_lib}_LIB
            NAMES ${_lib}
            PATHS "${WDK_KMLIB_DIR}"
            NO_DEFAULT_PATH
        )
        if(WDK_${_lib}_LIB)
            target_link_libraries(Ring0_CoreDriver PRIVATE ${WDK_${_lib}_LIB})
        else()
            # Fallback: link by absolute path if find_library misses it
            target_link_libraries(Ring0_CoreDriver PRIVATE "${WDK_KMLIB_DIR}/${_lib}.lib")
            message(WARNING "find_library did not locate ${_lib}.lib – using direct path fallback.")
        endif()
    endforeach()

    # ── Kernel Mode Definitions ──────────────────────────────────────────────
    target_compile_definitions(Ring0_CoreDriver PRIVATE
        _AMD64_
        AMD64
        _WIN64
        CONDITION_HANDLING=1
        NT_UP=1
        NT_INST=0
        WIN32=100
        _NT1X_=100
        WINNT=1
        _WIN32_WINNT=0x0A00
        WINVER=0x0A00
        _WIN32_IE=0x0A00
        EXLEVEL=4
        CRTDLL=1
        _M_AMD64
        KMDF_VERSION_MAJOR=1
    )
endif()

# ── Testing ───────────────────────────────────────────────────────────────────
enable_testing()
add_subdirectory(tests)
