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
    # Auto-detect: find the highest installed SDK version with km/ headers
    file(GLOB _SDK_VERSIONS LIST_DIRECTORIES true "${WDK_ROOT}/Include/10.*")
    set(WDK_VERSION "")
    foreach(_dir ${_SDK_VERSIONS})
        if(IS_DIRECTORY "${_dir}/km")
            get_filename_component(_ver "${_dir}" NAME)
            set(WDK_VERSION "${_ver}")
        endif()
    endforeach()
    if(NOT WDK_VERSION)
        message(FATAL_ERROR "Could not auto-detect WDK version. Install WDK or set WindowsSDKVersion.")
    endif()
    message(STATUS "Auto-detected WDK version: ${WDK_VERSION}")
endif()

set(WDK_INC_ROOT "${WDK_ROOT}/Include/${WDK_VERSION}")
set(WDK_LIB_ROOT "${WDK_ROOT}/Lib/${WDK_VERSION}")

# ── KMDF (WDF) paths ─────────────────────────────────────────────────────────
set(WDK_KMDF_INC "${WDK_ROOT}/Include/wdf/kmdf/1.33")
if(NOT EXISTS "${WDK_KMDF_INC}")
    # Fallback: find the highest installed KMDF version
    file(GLOB _KMDF_VERSIONS LIST_DIRECTORIES true "${WDK_ROOT}/Include/wdf/kmdf/*")
    list(LENGTH _KMDF_VERSIONS _KMDF_COUNT)
    if(_KMDF_COUNT GREATER 0)
        list(SORT _KMDF_VERSIONS COMPARE NATURAL ORDER DESCENDING)
        list(GET _KMDF_VERSIONS 0 WDK_KMDF_INC)
    endif()
endif()
set(WDK_KMDF_LIB "${WDK_ROOT}/Lib/wdf/kmdf/x64/1.33")
if(NOT EXISTS "${WDK_KMDF_LIB}")
    file(GLOB _KMDF_LIB_VERSIONS LIST_DIRECTORIES true "${WDK_ROOT}/Lib/wdf/kmdf/x64/*")
    list(LENGTH _KMDF_LIB_VERSIONS _KMDF_LIB_COUNT)
    if(_KMDF_LIB_COUNT GREATER 0)
        list(SORT _KMDF_LIB_VERSIONS COMPARE NATURAL ORDER DESCENDING)
        list(GET _KMDF_LIB_VERSIONS 0 WDK_KMDF_LIB)
    endif()
endif()

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
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Ring0_CoreDriver
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

if(MSVC)
    # ── WDK include directories ───────────────────────────────────────────────
    target_include_directories(Ring0_CoreDriver PRIVATE
        "${WDK_INC_ROOT}/km"
        "${WDK_INC_ROOT}/km/crt"
        "${WDK_INC_ROOT}/shared"
        "${WDK_KMDF_INC}"
    )

    # ── Compile options for kernel mode driver ────────────────────────────────
    target_compile_options(Ring0_CoreDriver PRIVATE
        "/kernel"              # Create kernel mode executable
        "/GR-"                 # Disable RTTI
        "/EHs-c-"              # Disable C++ exceptions
        "/Zc:threadSafeInit-"  # Disable thread-safe statics
        "/W4"                  # Warning level 4
        "/WX"                  # Treat warnings as errors
        "/wd4324"              # Suppress: struct padding from WDK headers
        "/wd4273"              # Suppress: ZwXxx inconsistent dll linkage from ntddk.h
        "/guard:cf"            # Control Flow Guard
        # "/Qspectre"            # Spectre Mitigation — TEMPORARILY DISABLED (requires Spectre libs)
        #                        # Manual _mm_lfence() already inserted at all critical bounds checks
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
        /guard:cf
        /NXCOMPAT
        /DYNAMICBASE
        /CETCOMPAT
        /PDBALTPATH:%_PDB%
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

    # ── KMDF framework libraries ─────────────────────────────────────────────
    if(EXISTS "${WDK_KMDF_LIB}")
        target_link_libraries(Ring0_CoreDriver PRIVATE
            "${WDK_KMDF_LIB}/WdfLdr.lib"
            "${WDK_KMDF_LIB}/WdfDriverEntry.lib"
        )
    else()
        message(WARNING "KMDF library directory not found: ${WDK_KMDF_LIB}")
    endif()

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
