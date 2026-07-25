// DynamicScanner.h
// [Ring 3 ONLY] Bộ quét động - Lớp kiểm duyệt chính ở User Mode.
//
// Luồng hoạt động (Ring-3 First Verification):
//   1. Quét liên tục danh sách tiến trình đang chạy trên hệ thống.
//   2. Với mỗi tiến trình MỚI chưa từng kiểm tra:
//      a. Lấy đường dẫn file thực thi (.exe).
//      b. Kiểm tra Chữ ký số (WinVerifyTrust) → Đây là bước kiểm duyệt Ring 3.
//      c. Tính toán SHA-256 của file để so sánh với Database nội bộ.
//   3. Sau khi có kết quả kiểm duyệt:
//      - An toàn:    Gọi DriverController::AddWhitelistPid() → Ring 0 bảo vệ tiến trình này.
//      - Nguy hiểm: Gọi DriverController::UpdateBlacklist()  → Ring 0 chặn tiến trình này ở Kernel.
//      - Nguy hiểm: Gọi MessageBridge để báo cáo lên React UI ngay lập tức.
//
// Nguyên tắc: Ring 3 kiểm tra TRƯỚC, Ring 0 hành động SAU theo quyết định của Ring 3.
#pragma once
#ifndef DYNAMIC_SCANNER_H
#define DYNAMIC_SCANNER_H

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <unordered_set>
#include <atomic>
#include <thread>
#include <functional>
#include <mutex>

#include "DriverController.h"
#include "MessageBridge.h"

// Kết quả kiểm duyệt của Ring 3
enum class ScanVerdict : UINT {
    UNKNOWN         = 0,
    TRUSTED         = 1,  // Có chữ ký số hợp lệ, đã báo Ring 0 whitelist
    SUSPICIOUS      = 2,  // Không có chữ ký số
    MALICIOUS       = 3,  // Hash hoặc tên khớp danh sách nguy hiểm → Ring 0 blacklist
};

struct ProcessRecord {
    DWORD       pid;
    std::wstring imagePath;
    std::wstring imageName;
    ScanVerdict  verdict;
    std::string  sha256Hex;   // Hash của file thực thi
    bool         signedOk;    // Có chữ ký số hợp lệ?
    bool         sentToRing0; // Đã gửi quyết định xuống Ring 0 chưa?
};

// Callback khi phát hiện tiến trình nguy hiểm
using ScanAlertCallback = std::function<void(const ProcessRecord& record)>;

class DynamicScanner {
public:
    DynamicScanner(DriverController& driver,
                   MessageBridge&    bridge,
                   const std::wstring& sessionToken);
    ~DynamicScanner();

    // Bắt đầu luồng quét nền
    void Start(DWORD intervalMs = 4000);
    void Stop();

    // Thêm tên tiến trình vào danh sách trắng nội bộ (không cần kiểm tra)
    void AddTrustedProcessName(const std::wstring& name);

    // Thêm SHA256 hash vào danh sách đen nội bộ (ngay lập tức block)
    void AddKnownBadHash(const std::string& sha256Hex);

    // Trả về toàn bộ lịch sử quét (để UI hiển thị)
    std::vector<ProcessRecord> GetScanHistory() const;

private:
    // ── Luồng chính ──────────────────────────────────────────────────────────
    void RunScanLoop(DWORD intervalMs);

    // ── Chụp ảnh tiến trình hiện tại ─────────────────────────────────────────
    std::vector<PROCESSENTRY32W> SnapshotRunningProcesses();

    // ── Bước kiểm duyệt (Ring-3 Verdict) ─────────────────────────────────────
    ScanVerdict AnalyzeProcess(DWORD pid, const std::wstring& imagePath,
                               std::string& outHash, bool& outSignedOk);

    // ── Kiểm tra chữ ký số (WinVerifyTrust) ──────────────────────────────────
    bool VerifyDigitalSignature(const std::wstring& filePath);

    // ── Tính SHA-256 của file ─────────────────────────────────────────────────
    std::string ComputeSHA256(const std::wstring& filePath);

    // ── Định tuyến quyết định xuống Ring 0 ───────────────────────────────────
    void RouteVerdictToRing0(const ProcessRecord& rec);

    // ── Lấy đường dẫn đầy đủ của tiến trình theo PID ─────────────────────────
    std::wstring GetProcessImagePath(DWORD pid);

    // ── Lấy tên file từ đường dẫn đầy đủ ────────────────────────────────────
    static std::wstring BaseName(const std::wstring& path);

    // ── Xây dựng gói JSON báo cáo lên React ──────────────────────────────────
    std::wstring BuildScanReportJson(const ProcessRecord& rec);

    // ── Thành viên ───────────────────────────────────────────────────────────
    DriverController&   m_driver;
    MessageBridge&      m_bridge;
    std::wstring        m_sessionToken;

    std::atomic<bool>   m_running{ false };
    std::thread         m_thread;
    mutable std::mutex  m_mutex;

    // Lịch sử đầy đủ để UI hiển thị
    std::vector<ProcessRecord>   m_history;

    // Cache danh sách tiến trình đã quét kèm thời gian tạo (Chống TOCTOU)
    std::map<DWORD, FILETIME> m_scannedPids;

    // Tên tiến trình hợp lệ được bỏ qua (hệ điều hành Windows, v.v.)
    std::unordered_set<std::wstring> m_trustedNames;

    // Hash SHA-256 của các phần mềm độc hại đã biết
    std::unordered_set<std::string> m_knownBadHashes;

    // Cache danh sách đen để tránh gọi UpdateBlacklist quá nhiều lần
    std::vector<std::wstring> m_pendingBlacklist;
    static constexpr size_t kMaxBlacklistBatch = 128;
};

#endif // DYNAMIC_SCANNER_H
