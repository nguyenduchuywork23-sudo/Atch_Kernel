// Logger.cpp
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#pragma warning(disable: 4996 4244)
#include "Logger.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <windows.h>
#include <codecvt>

Logger& Logger::GetInstance() {
    static Logger instance;
    return instance;
}

Logger::~Logger() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_file.is_open()) {
        m_file.close();
    }
}

void Logger::Init(const std::wstring& logFile) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_initialized) return;

    m_file.open(logFile, std::ios::out | std::ios::app);

    m_initialized = true;
    
    // Ghi dòng phân cách cho mỗi lần khởi động mới
    std::string timeStr = GetTimeStr();
    m_file << L"=================================================================\n";
    m_file << L"System Started at " << std::wstring(timeStr.begin(), timeStr.end()) << L"\n";
    m_file << L"=================================================================\n";
    m_file.flush();
}

std::string Logger::GetTimeStr() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::stringstream ss;
    struct tm timeinfo;
    localtime_s(&timeinfo, &in_time_t);
    ss << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S") << "." << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::string Logger::LevelToStr(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERR:   return "ERROR";
        default:              return "UNKNW";
    }
}

std::string Logger::GetFileName(const char* path) {
    std::string s(path);
    size_t pos = s.find_last_of("/\\");
    if (pos != std::string::npos) {
        return s.substr(pos + 1);
    }
    return s;
}

// Hàm ghi log cho chuỗi ANSI (std::string)
void Logger::Log(LogLevel level, const char* file, int line, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::string timeStr = GetTimeStr();
    std::string levelStr = LevelToStr(level);
    std::string fileName = GetFileName(file);
    
    // Format: [TIME] [LEVEL] [ThreadID] [File:Line] Message
    std::stringstream ss;
    ss << "[" << timeStr << "] "
       << "[" << levelStr << "] "
       << "[TID:" << std::setw(5) << GetCurrentThreadId() << "] "
       << "[" << fileName << ":" << line << "] "
       << message << "\n";
       
    std::string logLine = ss.str();
    
    // In ra console (nếu có)
    if (GetStdHandle(STD_OUTPUT_HANDLE) != NULL && GetStdHandle(STD_OUTPUT_HANDLE) != INVALID_HANDLE_VALUE) {
        std::cout << logLine;
    }
    OutputDebugStringA(logLine.c_str());

    // In ra file
    if (m_initialized && m_file.is_open()) {
        std::wstring wLogLine(logLine.begin(), logLine.end());
        m_file << wLogLine;
        m_file.flush();
    }
}

// Hàm ghi log cho chuỗi Unicode (std::wstring)
void Logger::Log(LogLevel level, const char* file, int line, const std::wstring& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::string timeStr = GetTimeStr();
    std::string levelStr = LevelToStr(level);
    std::string fileName = GetFileName(file);
    
    // Format prefix bằng string ANSI
    std::stringstream ss;
    ss << "[" << timeStr << "] "
       << "[" << levelStr << "] "
       << "[TID:" << std::setw(5) << GetCurrentThreadId() << "] "
       << "[" << fileName << ":" << line << "] ";
       
    std::string prefixStr = ss.str();
    std::wstring wPrefix(prefixStr.begin(), prefixStr.end());
    
    std::wstring fullLogLine = wPrefix + message + L"\n";
    
    // In ra màn hình console (chuyển tạm về string)
    // Lưu ý: Cửa sổ console Win32 đôi khi in utf8 bị lỗi nếu chưa set code page
    std::string ansiFull(fullLogLine.begin(), fullLogLine.end());
    if (GetStdHandle(STD_OUTPUT_HANDLE) != NULL && GetStdHandle(STD_OUTPUT_HANDLE) != INVALID_HANDLE_VALUE) {
        std::cout << ansiFull;
    }
    OutputDebugStringW(fullLogLine.c_str());

    // In ra file
    if (m_initialized && m_file.is_open()) {
        m_file << fullLogLine;
        m_file.flush();
    }
}
