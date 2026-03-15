#pragma once
// ============================================================================
// PhantomScope — file_scanner.h + graph_builder.h
// ============================================================================

#ifndef PHANTOMSCOPE_FILE_SCANNER_H
#define PHANTOMSCOPE_FILE_SCANNER_H

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <cstdint>

namespace PhantomScope {

enum class SignatureStatus : uint32_t {
    Valid    = 0,
    Unsigned = 1,
    Invalid  = 2,
    Untrusted = 3,
    Revoked  = 4,
    Unknown  = 5
};

struct SectionInfo {
    std::string name;
    uint32_t    virtual_size;
    uint32_t    raw_size;
    double      entropy;
    bool        is_executable;
    bool        is_writable;
};

struct ScannedFile {
    std::string  path;
    std::string  md5;
    std::string  sha256;
    double       entropy;
    uint32_t     entropy_class;   // 0=clean, 1=suspicious, 2=encrypted
    uint64_t     file_size;
    bool         is_64bit;
    bool         is_signed;
    bool         is_dotnet;
    bool         has_debug_info;
    bool         scanned;
    uint32_t     signature_status;
    uint64_t     compile_time;
    std::vector<std::string>  imported_dlls;
    std::vector<SectionInfo>  sections;
    int32_t      vt_detections;   // -1 = not queried
    std::string  threat_name;
    std::string  error_message;
    uint32_t     threat_score;    // 0-100
};

struct FileScanResult {
    std::vector<ScannedFile> files;
    uint32_t  high_entropy_count;
    uint32_t  vt_detected_count;
    uint32_t  unsigned_count;
    bool      success;
    std::string error_message;
};

struct ScanOptions {
    std::string  root_path;
    uint32_t     max_files;      // 0 = unlimited
    bool         scan_system_dirs;
    bool         follow_symlinks;
    std::vector<std::string> extra_exclusions;
    std::function<void(uint32_t, const std::string&)> progress_callback;
};

class FileScannerImpl;

class FileScanner {
public:
    FileScanner();
    ~FileScanner();

    FileScanResult ScanPath(const ScanOptions& options);
    ScannedFile    ScanSingleFile(const std::string& path);

private:
    std::unique_ptr<FileScannerImpl> impl_;
};

} // namespace PhantomScope

#endif // PHANTOMSCOPE_FILE_SCANNER_H
