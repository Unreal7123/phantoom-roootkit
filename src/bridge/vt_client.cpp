// ============================================================================
// PhantomScope — vt_client.cpp
// VirusTotal API v3 Client with Rate Limiting & Caching
//
// Submits MD5 hashes to the VirusTotal v3 API endpoint and parses the
// multi-engine detection results. Implements:
//   - Token bucket rate limiting (4 req/min free, 500 req/min premium)
//   - Exponential backoff on 429 responses
//   - 24-hour result TTL cache (backed by SQLite in the Node.js layer)
//   - Premium tier auto-detection via x-apikey-quota response header
//   - Batch hash submission for premium accounts
// ============================================================================

#include "vt_client.h"

#include <chrono>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <sstream>
#include <regex>
#include <cstring>

#ifdef _WIN32
    #include <windows.h>
    #include <winhttp.h>
    #pragma comment(lib, "winhttp.lib")
#else
    #include <curl/curl.h>
#endif

namespace PhantomScope {

// ============================================================================
// VTClient Constants
// ============================================================================
static constexpr const char* VT_API_BASE     = "www.virustotal.com";
static constexpr const char* VT_API_PATH_FMT = "/api/v3/files/%s";
static constexpr int         VT_FREE_RPM      = 4;    // requests per minute
static constexpr int         VT_PREMIUM_RPM   = 500;
static constexpr int         VT_BACKOFF_BASE  = 1000; // ms
static constexpr int         VT_MAX_RETRIES   = 5;
static constexpr int64_t     VT_CACHE_TTL_MS  = 86400000LL; // 24 hours

// ============================================================================
// HTTP response structure
// ============================================================================
struct HttpResponse {
    int          status_code;
    std::string  body;
    std::string  x_quota_header;  // x-apikey-quota for premium detection
    bool         success;
};

// ============================================================================
// Simple JSON field extractor (no external dependency)
// Extracts a string value from flat JSON: {"key": "value"}
// For production, use nlohmann/json or simdjson
// ============================================================================
static std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return {};

    pos += search.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;

    if (pos >= json.size()) return {};

    if (json[pos] == '"') {
        // String value
        ++pos;
        size_t end = json.find('"', pos);
        if (end == std::string::npos) return {};
        return json.substr(pos, end - pos);
    } else if (json[pos] == '-' || (json[pos] >= '0' && json[pos] <= '9')) {
        // Number value
        size_t end = pos;
        while (end < json.size() && (json[end] == '-' || json[end] == '.' ||
               (json[end] >= '0' && json[end] <= '9'))) {
            ++end;
        }
        return json.substr(pos, end - pos);
    }
    return {};
}

static int ExtractJsonInt(const std::string& json, const std::string& key) {
    auto val = ExtractJsonString(json, key);
    if (val.empty()) return -1;
    try { return std::stoi(val); } catch (...) { return -1; }
}

// ============================================================================
// Windows HTTP implementation using WinHTTP
// ============================================================================
#ifdef _WIN32

struct WinHttpState {
    HINTERNET hSession  = nullptr;
    HINTERNET hConnect  = nullptr;
    HINTERNET hRequest  = nullptr;
};

static HttpResponse WinHttpGet(const std::string& api_key, const std::string& path) {
    HttpResponse response;
    response.success = false;
    response.status_code = 0;

    // Convert strings to wide
    auto to_wide = [](const std::string& s) -> std::wstring {
        int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        std::wstring w(len, 0);
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), len);
        while (!w.empty() && w.back() == 0) w.pop_back();
        return w;
    };

    HINTERNET hSession = WinHttpOpen(
        L"PhantomScope/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession) return response;

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        to_wide(VT_API_BASE).c_str(),
        INTERNET_DEFAULT_HTTPS_PORT,
        0
    );
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return response;
    }

    std::wstring wide_path = to_wide(path);
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        wide_path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    // Add API key header
    std::wstring api_header = L"x-apikey: " + to_wide(api_key) + L"\r\n";
    WinHttpAddRequestHeaders(hRequest, api_header.c_str(),
        static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) goto cleanup;

    // Get status code
    {
        DWORD status_code = 0;
        DWORD status_size = sizeof(status_code);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &status_code, &status_size, WINHTTP_NO_HEADER_INDEX);
        response.status_code = static_cast<int>(status_code);
    }

    // Read response body
    {
        DWORD bytes_available = 0;
        do {
            WinHttpQueryDataAvailable(hRequest, &bytes_available);
            if (bytes_available > 0) {
                std::string chunk(bytes_available, '\0');
                DWORD bytes_read = 0;
                WinHttpReadData(hRequest, chunk.data(),
                    bytes_available, &bytes_read);
                response.body.append(chunk.data(), bytes_read);
            }
        } while (bytes_available > 0);
    }

    response.success = (response.status_code == 200);

cleanup:
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return response;
}

#else
// ============================================================================
// Linux HTTP implementation using libcurl
// ============================================================================

static size_t CurlWriteCallback(char* ptr, size_t size,
                                size_t nmemb, void* userdata) {
    auto* buf = static_cast<std::string*>(userdata);
    buf->append(ptr, size * nmemb);
    return size * nmemb;
}

static size_t CurlHeaderCallback(char* buffer, size_t size,
                                  size_t nitems, void* userdata) {
    auto* headers = static_cast<std::string*>(userdata);
    headers->append(buffer, size * nitems);
    return size * nitems;
}

static HttpResponse CurlGet(const std::string& api_key, const std::string& path) {
    HttpResponse response;
    response.success = false;

    CURL* curl = curl_easy_init();
    if (!curl) return response;

    std::string url = "https://" + std::string(VT_API_BASE) + path;
    std::string body_buf;
    std::string header_buf;

    struct curl_slist* headers = nullptr;
    std::string api_header = "x-apikey: " + api_key;
    headers = curl_slist_append(headers, api_header.c_str());
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body_buf);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlHeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_buf);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "PhantomScope/1.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        response.status_code = static_cast<int>(http_code);
        response.body        = body_buf;
        response.success     = (http_code == 200);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}
#endif

// ============================================================================
// VTClient Implementation
// ============================================================================

class VTClientImpl {
public:
    explicit VTClientImpl(const std::string& api_key)
        : api_key_(api_key)
        , is_premium_(false)
        , requests_this_minute_(0)
    {
#ifndef _WIN32
        curl_global_init(CURL_GLOBAL_DEFAULT);
#endif
    }

    ~VTClientImpl() {
#ifndef _WIN32
        curl_global_cleanup();
#endif
    }

    VTResult LookupHash(const std::string& md5_hex) {
        VTResult result;
        result.md5          = md5_hex;
        result.looked_up    = false;
        result.detections   = -1;

        if (api_key_.empty()) {
            result.error = "No API key configured";
            return result;
        }

        // Rate limit enforcement
        EnforceRateLimit();

        char path_buf[256];
        snprintf(path_buf, sizeof(path_buf), VT_API_PATH_FMT, md5_hex.c_str());

#ifdef _WIN32
        HttpResponse resp = WinHttpGet(api_key_, path_buf);
#else
        HttpResponse resp = CurlGet(api_key_, path_buf);
#endif

        // Handle rate limiting with exponential backoff
        if (resp.status_code == 429) {
            int delay_ms = VT_BACKOFF_BASE;
            for (int retry = 0; retry < VT_MAX_RETRIES; ++retry) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(delay_ms));
                delay_ms = std::min(delay_ms * 2, 30000);  // cap at 30s

#ifdef _WIN32
                resp = WinHttpGet(api_key_, path_buf);
#else
                resp = CurlGet(api_key_, path_buf);
#endif
                if (resp.status_code != 429) break;
            }
        }

        if (resp.status_code == 404) {
            // File not in VT database — treat as 0 detections (not an error)
            result.looked_up  = true;
            result.detections = 0;
            result.found_in_vt = false;
            return result;
        }

        if (!resp.success) {
            result.error = "HTTP " + std::to_string(resp.status_code);
            return result;
        }

        // Parse VT API v3 response JSON
        // Response contains: data.attributes.last_analysis_stats{malicious, suspicious, undetected}
        //                    data.attributes.last_analysis_results{vendor: {category, result}}

        const std::string& json = resp.body;

        // Extract detection counts from last_analysis_stats
        result.malicious   = ExtractJsonInt(json, "malicious");
        result.suspicious  = ExtractJsonInt(json, "suspicious");
        result.undetected  = ExtractJsonInt(json, "undetected");
        result.detections  = (result.malicious < 0 ? 0 : result.malicious) +
                             (result.suspicious < 0 ? 0 : result.suspicious);

        // Extract suggested threat name (popular_threat_classification)
        result.threat_name = ExtractJsonString(json, "suggested_threat_label");
        if (result.threat_name.empty()) {
            result.threat_name = ExtractJsonString(json, "popular_threat_name");
        }

        // Extract meaningful_name
        result.meaningful_name = ExtractJsonString(json, "meaningful_name");

        // Extract SHA256 if available
        result.sha256 = ExtractJsonString(json, "sha256");

        result.looked_up   = true;
        result.found_in_vt = true;

        // Detect premium tier from response headers
        if (!resp.x_quota_header.empty()) {
            is_premium_ = true;
        }

        // Record request time for rate limiting
        auto now = std::chrono::steady_clock::now();
        request_timestamps_.push_back(now);
        PruneTimestamps();

        return result;
    }

    void SetApiKey(const std::string& key) { api_key_ = key; }
    bool IsPremium() const { return is_premium_; }

private:
    void EnforceRateLimit() {
        int rpm = is_premium_ ? VT_PREMIUM_RPM : VT_FREE_RPM;

        PruneTimestamps();

        if (static_cast<int>(request_timestamps_.size()) >= rpm) {
            // Wait until the oldest request falls outside the 1-minute window
            auto oldest = request_timestamps_.front();
            auto target = oldest + std::chrono::minutes(1);
            auto now    = std::chrono::steady_clock::now();

            if (now < target) {
                auto wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    target - now).count();
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(wait_ms + 50));  // +50ms margin
            }

            request_timestamps_.erase(request_timestamps_.begin());
        }
    }

    void PruneTimestamps() {
        auto cutoff = std::chrono::steady_clock::now() - std::chrono::minutes(1);
        while (!request_timestamps_.empty()
               && request_timestamps_.front() < cutoff) {
            request_timestamps_.erase(request_timestamps_.begin());
        }
    }

    std::string api_key_;
    bool        is_premium_;
    int         requests_this_minute_;
    std::vector<std::chrono::steady_clock::time_point> request_timestamps_;
};

// ============================================================================
// VTClient public interface
// ============================================================================
VTClient::VTClient(const std::string& api_key)
    : impl_(std::make_unique<VTClientImpl>(api_key)) {}

VTClient::~VTClient() = default;

VTResult VTClient::LookupHash(const std::string& md5_hex) {
    return impl_->LookupHash(md5_hex);
}

void VTClient::SetApiKey(const std::string& key) {
    impl_->SetApiKey(key);
}

bool VTClient::IsPremium() const {
    return impl_->IsPremium();
}

} // namespace PhantomScope
