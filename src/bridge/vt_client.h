#pragma once
#ifndef PHANTOMSCOPE_VT_CLIENT_H
#define PHANTOMSCOPE_VT_CLIENT_H

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace PhantomScope {

struct VTVendorResult {
    std::string vendor_name;
    std::string category;       // "malicious", "suspicious", "undetected"
    std::string engine_name;
    std::string result;         // Detection label if positive
};

struct VTResult {
    std::string md5;
    std::string sha256;
    std::string threat_name;
    std::string meaningful_name;
    int32_t     detections;     // malicious + suspicious count, -1 = not queried
    int32_t     malicious;
    int32_t     suspicious;
    int32_t     undetected;
    bool        looked_up;
    bool        found_in_vt;
    std::string error;
    std::vector<VTVendorResult> vendor_results;
    int64_t     cache_time;     // Unix timestamp when this was cached
};

class VTClientImpl;

class VTClient {
public:
    explicit VTClient(const std::string& api_key = "");
    ~VTClient();

    VTResult LookupHash(const std::string& md5_hex);
    void     SetApiKey(const std::string& key);
    bool     IsPremium() const;

private:
    std::unique_ptr<VTClientImpl> impl_;
};

} // namespace PhantomScope

#endif // PHANTOMSCOPE_VT_CLIENT_H
