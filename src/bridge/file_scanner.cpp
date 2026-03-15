// ============================================================================
// PhantomScope — file_scanner.cpp
// Filesystem Walker + PE/ELF Binary Parser
//
// Recursively walks target directories, identifies PE (Windows) and ELF
// (Linux) executables, and extracts security-relevant metadata including:
//   - Import tables (loaded DLLs / .so files)
//   - Section entropy (per-section packed code detection)
//   - Digital signature status
//   - Service binary paths
//   - Unquoted service path hijack vectors
// ============================================================================

#include "file_scanner.h"
#include "asm_bridge.h"
#include "pe_parser.h"
#include "elf_parser.h"

#include <filesystem>
#include <vector>
#include <string>
#include <unordered_set>
#include <memory>
#include <algorithm>
#include <cstring>
#include <regex>

#ifdef _WIN32
    #include <windows.h>
    #include <wintrust.h>
    #include <softpub.h>
    #include <wincrypt.h>
    #pragma comment(lib, "wintrust.lib")
    #pragma comment(lib, "crypt32.lib")
#endif

namespace fs = std::filesystem;
namespace PhantomScope {

// ============================================================================
// Default scan exclusion list
// ============================================================================
static const std::unordered_set<std::string> DEFAULT_EXCLUSIONS_WIN = {
    "C:\\Windows\\Installer",
    "C:\\Windows\\SoftwareDistribution",
    "C:\\Windows\\WinSxS",
};

static const std::unordered_set<std::string> DEFAULT_EXCLUSIONS_LIN = {
    "/proc", "/sys", "/dev", "/run/lock",
    "/tmp/.private", "/var/cache/apt",
};

// PE file extensions to scan
static const std::unordered_set<std::string> PE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv", ".ax"
};

// ELF file detection: check magic bytes (no extension on Linux)
static bool IsElfBinary(const std::string& path) {
    unsigned char magic[4] = {};
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    size_t read = fread(magic, 1, 4, f);
    fclose(f);
    return read == 4 && magic[0] == 0x7F && magic[1] == 'E'
        && magic[2] == 'L' && magic[3] == 'F';
}

static bool IsPeBinary(const std::string& path) {
    unsigned char magic[2] = {};
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    size_t read = fread(magic, 1, 2, f);
    fclose(f);
    return read == 2 && magic[0] == 'M' && magic[1] == 'Z';
}

// ============================================================================
// Digital signature verification (Windows only)
// ============================================================================
#ifdef _WIN32
static SignatureStatus CheckDigitalSignature(const std::wstring& file_path) {
    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct    = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = file_path.c_str();

    WINTRUST_DATA trust_data = {};
    trust_data.cbStruct            = sizeof(WINTRUST_DATA);
    trust_data.dwUIChoice          = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;  // No revocation for speed
    trust_data.dwUnionChoice       = WTD_CHOICE_FILE;
    trust_data.pFile               = &file_info;
    trust_data.dwStateAction       = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags         = WTD_SAFER_FLAG;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG result = WinVerifyTrust(nullptr, &action, &trust_data);

    // Clean up state
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trust_data);

    if (result == ERROR_SUCCESS)           return SignatureStatus::Valid;
    if (result == TRUST_E_NOSIGNATURE)     return SignatureStatus::Unsigned;
    if (result == TRUST_E_SUBJECT_NOT_TRUSTED) return SignatureStatus::Untrusted;
    if (result == CERT_E_REVOKED)          return SignatureStatus::Revoked;
    return SignatureStatus::Invalid;
}
#endif

// ============================================================================
// FileScannerImpl
// ============================================================================
class FileScannerImpl {
public:
    FileScannerImpl() {
        PhantomScope::AsmCore::Initialize();
    }

    FileScanResult ScanPath(const ScanOptions& options) {
        FileScanResult result;
        result.success = true;

        // Build exclusion set
        std::unordered_set<std::string> exclusions;
#ifdef _WIN32
        exclusions = DEFAULT_EXCLUSIONS_WIN;
#else
        exclusions = DEFAULT_EXCLUSIONS_LIN;
#endif
        for (const auto& ex : options.extra_exclusions) {
            exclusions.insert(ex);
        }

        // Walk directory tree
        try {
            for (const auto& dir_entry : fs::recursive_directory_iterator(
                    options.root_path,
                    fs::directory_options::skip_permission_denied))
            {
                const auto& path = dir_entry.path();

                // Skip excluded directories
                bool excluded = false;
                for (const auto& ex : exclusions) {
                    if (path.string().rfind(ex, 0) == 0) {
                        excluded = true;
                        break;
                    }
                }
                if (excluded) continue;

                if (!dir_entry.is_regular_file()) continue;

                // Check if this is a binary we want to scan
                std::string path_str = path.string();
                bool is_binary = false;

#ifdef _WIN32
                std::string ext = path.extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (PE_EXTENSIONS.count(ext)) is_binary = IsPeBinary(path_str);
#else
                // On Linux: check ELF magic, or scan executables by permission
                is_binary = IsElfBinary(path_str);
                if (!is_binary) {
                    // Also check +x files
                    std::error_code ec;
                    auto perms = fs::status(path, ec).permissions();
                    if (!ec && (perms & fs::perms::owner_exec) != fs::perms::none) {
                        is_binary = true;
                    }
                }
#endif

                if (!is_binary) continue;

                ScannedFile sf = ScanFile(path_str);
                result.files.push_back(std::move(sf));

                // Progress callback
                if (options.progress_callback) {
                    options.progress_callback(
                        static_cast<uint32_t>(result.files.size()),
                        path_str
                    );
                }

                // Limit for testing / partial scans
                if (options.max_files > 0
                        && result.files.size() >= options.max_files) {
                    break;
                }
            }
        } catch (const fs::filesystem_error& e) {
            result.error_message = e.what();
            // Don't fail the whole scan on a permission error
        }

        // Post-process: calculate overall stats
        for (const auto& f : result.files) {
            if (f.entropy > 6.5)      ++result.high_entropy_count;
            if (f.vt_detections > 0)  ++result.vt_detected_count;
            if (!f.is_signed)         ++result.unsigned_count;
        }

        return result;
    }

    ScannedFile ScanFile(const std::string& path) {
        ScannedFile sf;
        sf.path = path;
        sf.scanned = false;

        try {
            // File size
            std::error_code ec;
            sf.file_size = static_cast<uint64_t>(
                fs::file_size(path, ec));
            if (ec) return sf;

            // MD5 hash (NASM)
            AsmMD5Result md5_result;
            if (AsmCore::ComputeFileMD5(path.c_str(), md5_result)) {
                sf.md5 = md5_result.hex;
            }

            // Shannon entropy (NASM)
            AsmEntropyResult entropy_result;
            if (AsmCore::ComputeFileEntropy(path.c_str(), entropy_result)) {
                sf.entropy        = entropy_result.value;
                sf.entropy_class  = static_cast<uint32_t>(entropy_result.classification);
            }

            // Binary format parsing
#ifdef _WIN32
            if (IsPeBinary(path)) {
                PEParser pe(path);
                if (pe.Parse()) {
                    sf.imported_dlls   = pe.GetImports();
                    sf.sections        = pe.GetSections();
                    sf.is_64bit        = pe.Is64Bit();
                    sf.has_debug_info  = pe.HasDebugDirectory();
                    sf.is_dotnet       = pe.IsDotNet();
                    sf.compile_time    = pe.GetTimestamp();

                    // Check digital signature
                    std::wstring wide_path(path.begin(), path.end());
                    sf.signature_status = static_cast<uint32_t>(
                        CheckDigitalSignature(wide_path));
                    sf.is_signed = (sf.signature_status ==
                        static_cast<uint32_t>(SignatureStatus::Valid));
                }
            }
#else
            if (IsElfBinary(path)) {
                ELFParser elf(path);
                if (elf.Parse()) {
                    sf.imported_dlls = elf.GetDependencies();
                    sf.sections      = elf.GetSections();
                    sf.is_64bit      = elf.Is64Bit();
                }
                sf.is_signed = false;  // ELF signing is uncommon
            }
#endif

            sf.scanned = true;

        } catch (const std::exception& e) {
            sf.error_message = e.what();
        }

        return sf;
    }
};

// ============================================================================
// FileScanner public interface
// ============================================================================
FileScanner::FileScanner()
    : impl_(std::make_unique<FileScannerImpl>()) {}

FileScanner::~FileScanner() = default;

FileScanResult FileScanner::ScanPath(const ScanOptions& options) {
    return impl_->ScanPath(options);
}

ScannedFile FileScanner::ScanSingleFile(const std::string& path) {
    return impl_->ScanFile(path);
}

} // namespace PhantomScope
