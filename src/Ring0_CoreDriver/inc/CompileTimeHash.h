#pragma once

#ifndef COMPILE_TIME_HASH_H
#define COMPILE_TIME_HASH_H

#include <ntifs.h>

// FNV-1a Hash constants for 32-bit
constexpr ULONG FNV_PRIME_32 = 16777619u;
constexpr ULONG FNV_OFFSET_BASIS_32 = 2166136261u;

// Helper to lowercase WCHAR at compile time
constexpr WCHAR ToLowerW(WCHAR c) {
    return (c >= L'A' && c <= L'Z') ? (c + (L'a' - L'A')) : c;
}

// Compile-time FNV-1a hash function for wide strings (case-insensitive)
constexpr ULONG CompileTimeHashW(const wchar_t* str, ULONG hash = FNV_OFFSET_BASIS_32) {
    return (*str == L'\0') ? hash : CompileTimeHashW(str + 1, (hash ^ static_cast<ULONG>(ToLowerW(*str))) * FNV_PRIME_32);
}

// Runtime FNV-1a hash function for UNICODE_STRING (case-insensitive)
inline ULONG RuntimeHashUnicodeString(PCUNICODE_STRING uniStr) {
    if (!uniStr || !uniStr->Buffer) return 0;
    
    ULONG hash = FNV_OFFSET_BASIS_32;
    USHORT chars = uniStr->Length / sizeof(WCHAR);
    
    for (USHORT i = 0; i < chars; ++i) {
        // OMEGA-XIX: Stop at null terminator to match CompileTimeHashW behavior
        if (uniStr->Buffer[i] == L'\0') break;
        WCHAR c = ToLowerW(uniStr->Buffer[i]);
        hash = (hash ^ static_cast<ULONG>(c)) * FNV_PRIME_32;
    }
    
    return hash;
}

// Runtime FNV-1a hash for WCHAR buffer without length
inline ULONG RuntimeHashBuffer(const WCHAR* buffer, USHORT chars) {
    if (!buffer) return 0;
    
    ULONG hash = FNV_OFFSET_BASIS_32;
    for (USHORT i = 0; i < chars; ++i) {
        // OMEGA-XX: Stop at null to match CompileTimeHashW/RuntimeHashUnicodeString
        if (buffer[i] == L'\0') break;
        WCHAR c = ToLowerW(buffer[i]);
        hash = (hash ^ static_cast<ULONG>(c)) * FNV_PRIME_32;
    }
    
    return hash;
}

#endif // COMPILE_TIME_HASH_H
