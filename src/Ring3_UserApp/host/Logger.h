// Logger.h
#pragma once

#include <string>
#include <mutex>
#include <fstream>
#include <sstream>

enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERR 
};

class Logger {
public:
    static Logger& GetInstance();
    
    void Init(const std::wstring& logFile);
    void Log(LogLevel level, const char* file, int line, const std::string& message);
    void Log(LogLevel level, const char* file, int line, const std::wstring& message);

private:
    Logger() = default;
    ~Logger();

    // Khởi tạo không copy
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::string GetTimeStr();
    std::string LevelToStr(LogLevel level);
    std::string GetFileName(const char* path);

    std::wofstream m_file;
    std::mutex m_mutex;
    bool m_initialized = false;
};

// Helper macros để ghi log nhanh và tự động lấy thông tin File, Line
#define LOG_DEBUG(msg) Logger::GetInstance().Log(LogLevel::DEBUG, __FILE__, __LINE__, msg)
#define LOG_INFO(msg)  Logger::GetInstance().Log(LogLevel::INFO,  __FILE__, __LINE__, msg)
#define LOG_WARN(msg)  Logger::GetInstance().Log(LogLevel::WARN,  __FILE__, __LINE__, msg)
#define LOG_ERR(msg)   Logger::GetInstance().Log(LogLevel::ERR,   __FILE__, __LINE__, msg)
