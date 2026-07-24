// DynamicScanner.cpp
// [Ring 3 ONLY] Triển khai Bộ quét động (Ring-3 First Verification).
//
// Đây là trái tim của cơ chế: "Mọi thứ phải qua Ring 3 kiểm duyệt TRƯỚC,
// Ring 0 chỉ hành động THEO QUYẾT ĐỊNH của Ring 3."
#define NOMINMAX
#include "DynamicScanner.h"
#include "Logger.h"
#include <windows.h>
#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>
#include <array>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")

// ─── Danh sách tên tiến trình Windows hệ thống luôn được tin cậy ──────────────
// Ring 3 bỏ qua các tiến trình này để tiết kiệm CPU và tránh false positive.
static const wchar_t* kWindowsSystemProcesses[] = {
    L"system",         L"smss.exe",       L"csrss.exe",
    L"wininit.exe",    L"winlogon.exe",   L"services.exe",
    L"lsass.exe",      L"lsm.exe",        L"svchost.exe",
    L"dwm.exe",        L"explorer.exe",   L"taskhostw.exe",
    L"sihost.exe",     L"runtimebroker.exe", L"conhost.exe",
    L"dllhost.exe",    L"wfds.exe",       L"fontdrvhost.exe",
    L"searchindexer.exe", L"audiodg.exe", L"spoolsv.exe",
    L"ntoskrnl.exe",   L"registry",
};

DynamicScanner::DynamicScanner(DriverController& driver,
                               MessageBridge&    bridge,
                               const std::wstring& sessionToken)
    : m_driver(driver)
    , m_bridge(bridge)
    , m_sessionToken(sessionToken)
{
    // Nạp danh sách tiến trình hệ thống vào bộ nhớ để bỏ qua
    for (auto& name : kWindowsSystemProcesses) {
        std::wstring lowerName = name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
        m_trustedNames.insert(lowerName);
    }
}

DynamicScanner::~DynamicScanner()
{
    Stop();
}

// ─── API công khai ─────────────────────────────────────────────────────────────
void DynamicScanner::AddTrustedProcessName(const std::wstring& name)
{
    std::wstring lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    std::lock_guard<std::mutex> lk(m_mutex);
    m_trustedNames.insert(lower);
}

void DynamicScanner::AddKnownBadHash(const std::string& sha256Hex)
{
    std::lock_guard<std::mutex> lk(m_mutex);
    m_knownBadHashes.insert(sha256Hex);
}

std::vector<ProcessRecord> DynamicScanner::GetScanHistory() const
{
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_history;
}

void DynamicScanner::Start(DWORD intervalMs)
{
    LOG_INFO("DynamicScanner: Starting up...");

    m_running = true;
    m_thread = std::thread([this, intervalMs]() {
        LOG_INFO("DynamicScanner: Thread started.");
        RunScanLoop(intervalMs);
        LOG_INFO("DynamicScanner: Thread stopped.");
    });
}

void DynamicScanner::Stop()
{
    LOG_INFO("DynamicScanner: Stop requested.");
    m_running = false;
    if (m_thread.joinable())
        m_thread.join();
}

// ─── Vòng lặp quét chính ───────────────────────────────────────────────────────
void DynamicScanner::RunScanLoop(DWORD intervalMs)
{
    while (m_running.load()) {
        auto processes = SnapshotRunningProcesses();

        for (auto& pe : processes) {
            DWORD pid = pe.th32ProcessID;

            {
                std::lock_guard<std::mutex> lk(m_mutex);
                // Bỏ qua nếu đã kiểm tra PID này trong phiên
                if (m_scannedPids.count(pid)) continue;
            }

            // Lấy đường dẫn đầy đủ
            std::wstring imagePath = GetProcessImagePath(pid);
            std::wstring imageName = BaseName(imagePath.empty()
                                              ? pe.szExeFile
                                              : imagePath);
            std::wstring lowerName = imageName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

            {
                std::lock_guard<std::mutex> lk(m_mutex);
                // Bỏ qua tiến trình hệ thống đã biết
                if (m_trustedNames.count(lowerName)) {
                    m_scannedPids.insert(pid);
                    continue;
                }
            }

            // ─── [RING 3 VERDICT] Phân tích file ───────────────────────────────
            LOG_INFO(L"DynamicScanner: New process detected [PID: " + std::to_wstring(pid) + L"] " + lowerName);

            std::string  sha256Hex;
            bool         signedOk = false;
            ScanVerdict  verdict  = ScanVerdict::UNKNOWN;

            if (!imagePath.empty()) {
                verdict = AnalyzeProcess(pid, imagePath, sha256Hex, signedOk);
            } else {
                // Không lấy được đường dẫn → coi là đáng ngờ
                verdict   = ScanVerdict::SUSPICIOUS;
                signedOk  = false;
            }

            // Xây dựng bản ghi
            ProcessRecord rec{};
            rec.pid        = pid;
            rec.imagePath  = imagePath.empty() ? pe.szExeFile : imagePath;
            rec.imageName  = imageName;
            rec.verdict    = verdict;
            rec.sha256Hex  = sha256Hex;
            rec.signedOk   = signedOk;
            rec.sentToRing0 = false;

            // ─── [ĐỊNH TUYẾN RING 0] Gửi quyết định xuống Kernel ──────────────
            RouteVerdictToRing0(rec);
            rec.sentToRing0 = true;

            // ─── [BÁO CÁO UI] Gửi thông tin lên React ─────────────────────────
            if (verdict == ScanVerdict::MALICIOUS || verdict == ScanVerdict::SUSPICIOUS) {
                m_bridge.PostToReact(BuildScanReportJson(rec));
            }

            {
                std::lock_guard<std::mutex> lk(m_mutex);
                m_scannedPids.insert(pid);
                m_history.push_back(rec);
            }
        }

        // Chờ đến chu kỳ quét tiếp theo (kiểm tra m_running mỗi 100ms để thoát nhanh)
        for (DWORD i = 0; i < intervalMs; i += 100) {
            if (!m_running.load()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

// ─── Chụp ảnh danh sách tiến trình ────────────────────────────────────────────
std::vector<PROCESSENTRY32W> DynamicScanner::SnapshotRunningProcesses()
{
    std::vector<PROCESSENTRY32W> result;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return result;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            result.push_back(pe);
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return result;
}

// ─── Phân tích tiến trình (Bước kiểm duyệt Ring 3) ────────────────────────────
ScanVerdict DynamicScanner::AnalyzeProcess(DWORD /*pid*/, const std::wstring& imagePath,
                                           std::string& outHash, bool& outSignedOk)
{
    // Bước 1: Kiểm tra chữ ký số
    outSignedOk = VerifyDigitalSignature(imagePath);

    // Bước 2: Tính SHA-256 của file thực thi
    outHash = ComputeSHA256(imagePath);

    // Bước 3: So sánh hash với danh sách đen nội bộ
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (!outHash.empty() && m_knownBadHashes.count(outHash)) {
            // Hash khớp danh sách đen → Phần mềm độc hại đã biết
            return ScanVerdict::MALICIOUS;
        }
    }

    // Bước 4: Phán quyết dựa trên chữ ký số
    if (outSignedOk) {
        return ScanVerdict::TRUSTED;
    } else {
        // Không có chữ ký số hợp lệ → Đáng ngờ
        return ScanVerdict::SUSPICIOUS;
    }
}

// ─── Kiểm tra Chữ ký số (WinVerifyTrust) ─────────────────────────────────────
// Đây là cơ chế kiểm duyệt chính của Ring 3.
// WinVerifyTrust gọi Windows Authenticode để xác thực chuỗi chứng chỉ.
bool DynamicScanner::VerifyDigitalSignature(const std::wstring& filePath)
{
    // WinVerifyTrust yêu cầu file path không const nên ta tạo bản sao
    std::vector<wchar_t> pathBuf(filePath.begin(), filePath.end());
    pathBuf.push_back(L'\0');

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct       = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath  = pathBuf.data();
    fileInfo.hFile          = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    // GUID của Authenticode Policy Provider
    GUID wvtPolGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wvtData{};
    wvtData.cbStruct            = sizeof(WINTRUST_DATA);
    wvtData.pPolicyCallbackData = nullptr;
    wvtData.pSIPClientData      = nullptr;
    wvtData.dwUIChoice          = WTD_UI_NONE;        // Không hiển thị dialog
    wvtData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN; // Kiểm tra revocation
    wvtData.dwUnionChoice       = WTD_CHOICE_FILE;
    wvtData.dwStateAction       = WTD_STATEACTION_VERIFY;
    wvtData.hWVTStateData       = nullptr;
    wvtData.pwszURLReference    = nullptr;
    wvtData.dwUIContext         = 0;
    wvtData.pFile               = &fileInfo;

    LONG result = WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &wvtPolGuid,
        &wvtData);

    // Dọn dẹp state sau khi verify
    wvtData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &wvtPolGuid, &wvtData);

    // TRUST_E_NOSIGNATURE     (-2146869244) = Không có chữ ký
    // TRUST_E_BAD_DIGEST      (-2146869232) = Chữ ký bị hỏng
    // CERT_E_REVOKED          (-2146762484) = Cert đã bị thu hồi
    // ERROR_SUCCESS           (0)           = Hợp lệ
    return (result == ERROR_SUCCESS);
}

// ─── Tính toán SHA-256 bằng Windows CryptoAPI ─────────────────────────────────
std::string DynamicScanner::ComputeSHA256(const std::wstring& filePath)
{
    // Mở file để đọc
    HANDLE hFile = CreateFileW(filePath.c_str(),
                               GENERIC_READ,
                               FILE_SHARE_READ,
                               nullptr,
                               OPEN_EXISTING,
                               FILE_FLAG_SEQUENTIAL_SCAN,
                               nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return {};

    // Khởi tạo CryptAPI
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        CloseHandle(hFile);
        return {};
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return {};
    }

    // Đọc và hash từng chunk 4MB
    const DWORD kChunkSize = 4 * 1024 * 1024;
    std::vector<BYTE> buf(kChunkSize);
    DWORD bytesRead = 0;
    bool  ok        = true;

    while (ok) {
        if (!ReadFile(hFile, buf.data(), kChunkSize, &bytesRead, nullptr)) {
            ok = false;
            break;
        }
        if (bytesRead == 0) break; // EOF

        if (!CryptHashData(hHash, buf.data(), bytesRead, 0)) {
            ok = false;
            break;
        }
    }

    if (ok) {
        DWORD hashLen = 0;
        DWORD cbHashLen = sizeof(DWORD);
        if (CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &cbHashLen, 0)) {
            std::vector<BYTE> hashBytes(hashLen);
            if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes.data(), &hashLen, 0)) {
                // Chuyển thành chuỗi hex
                std::ostringstream ss;
                for (auto b : hashBytes)
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
                result = ss.str();
            }
        }
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return result;
}

// ─── Định tuyến quyết định xuống Ring 0 ────────────────────────────────────────
// Đây là bước "gửi quyết định về Ring 0" theo yêu cầu của bạn.
void DynamicScanner::RouteVerdictToRing0(const ProcessRecord& rec)
{
    if (!m_driver.IsOpen()) return;

    switch (rec.verdict) {
    case ScanVerdict::TRUSTED:
        // ✅ Ring 3 đã xác nhận file này an toàn.
        // → Báo Ring 0 whitelist PID này: Ring 0 sẽ bảo vệ tiến trình này.
        m_driver.AddWhitelistPid(m_sessionToken.c_str(), rec.pid);
        break;

    case ScanVerdict::MALICIOUS:
        // ❌ Ring 3 xác nhận file này là phần mềm độc hại (hash khớp DB).
        // → Báo Ring 0 đưa vào blacklist: Ring 0 sẽ chặn mọi hành vi của nó.
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            m_pendingBlacklist.push_back(rec.imageName);

            // Flush xuống Ring 0 theo batch (tối đa kMaxBlacklistBatch items)
            if (m_pendingBlacklist.size() >= 1) { // Flush ngay với MALICIOUS
                ULONG count = static_cast<ULONG>(
                    std::min(m_pendingBlacklist.size(), kMaxBlacklistBatch));

                // Tạo mảng WCHAR[256] để truyền xuống driver
                std::vector<std::array<WCHAR, 256>> items(count);
                for (ULONG i = 0; i < count; ++i) {
                    wcsncpy_s(items[i].data(), 256, m_pendingBlacklist[i].c_str(), _TRUNCATE);
                }

                m_driver.UpdateBlacklist(
                    m_sessionToken.c_str(),
                    reinterpret_cast<const WCHAR(*)[256]>(items.data()),
                    count);

                m_pendingBlacklist.erase(
                    m_pendingBlacklist.begin(),
                    m_pendingBlacklist.begin() + count);
            }
        }
        break;

    case ScanVerdict::SUSPICIOUS:
        // ⚠️ Ring 3 thấy file không có chữ ký số.
        // → Đưa vào blacklist để Ring 0 ngăn chặn trước khi nó có thể làm gì.
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            m_pendingBlacklist.push_back(rec.imageName);

            if (m_pendingBlacklist.size() >= 1) {
                ULONG count = static_cast<ULONG>(
                    std::min(m_pendingBlacklist.size(), kMaxBlacklistBatch));

                std::vector<std::array<WCHAR, 256>> items(count);
                for (ULONG i = 0; i < count; ++i) {
                    wcsncpy_s(items[i].data(), 256, m_pendingBlacklist[i].c_str(), _TRUNCATE);
                }

                m_driver.UpdateBlacklist(
                    m_sessionToken.c_str(),
                    reinterpret_cast<const WCHAR(*)[256]>(items.data()),
                    count);

                m_pendingBlacklist.erase(
                    m_pendingBlacklist.begin(),
                    m_pendingBlacklist.begin() + count);
            }
        }
        break;

    default:
        break;
    }
}

// ─── Lấy đường dẫn đầy đủ của tiến trình ─────────────────────────────────────
std::wstring DynamicScanner::GetProcessImagePath(DWORD pid)
{
    // Mở tiến trình để lấy đường dẫn thực thi
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        LOG_WARN("DynamicScanner: Could not open handle for new process " + std::to_string(pid));
        return L""; 
    }

    WCHAR imagePath[MAX_PATH]{};
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProc, 0, imagePath, &size)) {
        LOG_WARN("DynamicScanner: Could not query image name for " + std::to_string(pid));
        CloseHandle(hProc);
        return L"";
    }
    CloseHandle(hProc);

    std::wstring fullPath(imagePath);
    LOG_DEBUG(L"DynamicScanner: Analyzing " + std::to_wstring(pid) + L" -> " + fullPath);
    return fullPath;
}

// ─── Lấy tên file từ đường dẫn ────────────────────────────────────────────────
std::wstring DynamicScanner::BaseName(const std::wstring& path)
{
    auto pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return path;
    return path.substr(pos + 1);
}

// ─── Xây dựng JSON báo cáo lên React ─────────────────────────────────────────
std::wstring DynamicScanner::BuildScanReportJson(const ProcessRecord& rec)
{
    const wchar_t* verdictStr = L"UNKNOWN";
    switch (rec.verdict) {
    case ScanVerdict::TRUSTED:    verdictStr = L"TRUSTED";    break;
    case ScanVerdict::SUSPICIOUS: verdictStr = L"SUSPICIOUS"; break;
    case ScanVerdict::MALICIOUS:  verdictStr = L"MALICIOUS";  break;
    default: break;
    }

    // Chuyển SHA256 (std::string) sang wstring
    std::wstring hashW(rec.sha256Hex.begin(), rec.sha256Hex.end());

    std::wostringstream ss;
    ss << L"{\"type\":\"SCAN_RESULT\","
       << L"\"payload\":{"
       << L"\"pid\":"         << rec.pid          << L","
       << L"\"imageName\":\"" << rec.imageName     << L"\","
       << L"\"imagePath\":\"" << rec.imagePath     << L"\","
       << L"\"verdict\":\""   << verdictStr        << L"\","
       << L"\"signed\":"      << (rec.signedOk ? L"true" : L"false") << L","
       << L"\"sha256\":\""    << hashW             << L"\","
       << L"\"sentToRing0\":" << (rec.sentToRing0 ? L"true" : L"false")
       << L"}}";

    return ss.str();
}
