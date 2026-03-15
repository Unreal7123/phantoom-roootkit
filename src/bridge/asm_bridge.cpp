// ============================================================================
// PhantomScope — asm_bridge.cpp
// C++ ↔ NASM Assembly Bridge Implementation
//
// Implements the AsmCore wrapper class and handles:
//   - CPU feature detection (SSE2, SSE4.1)
//   - SSN resolution initialization
//   - Memory-mapped file I/O for MD5/entropy
//   - MD5 hex formatting
// ============================================================================

#include "asm_bridge.h"

#include <cstring>
#include <cstdio>
#include <cassert>
#include <stdexcept>
#include <string>
#include <array>

#ifdef _WIN32
    #include <windows.h>
    #include <intrin.h>
#else
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <cpuid.h>
#endif

namespace PhantomScope {

// ============================================================================
// Static member initialization
// ============================================================================
bool AsmCore::s_initialized       = false;
bool AsmCore::s_sse41_available   = false;
bool AsmCore::s_sse2_available    = false;

// ============================================================================
// AsmCore::Initialize
// ============================================================================
bool AsmCore::Initialize() {
    if (s_initialized) return true;

    // Detect CPU features via CPUID
    s_sse2_available  = HasSSE2Support();
    s_sse41_available = HasSSE41Support();

#ifdef _WIN32
    // Resolve all NT syscall SSNs dynamically
    int resolved = AsmResolveAllSSNs();
    if (resolved == 0) {
        // Critical failure: no SSNs resolved
        // This can happen if ntdll.dll is heavily patched or we're in a sandbox
        // Fall back to using hardcoded SSNs for Win10 21H2
        // The C++ bridge will retry with user-mode APIs as fallback
        fprintf(stderr, "[PhantomScope] WARNING: SSN resolution failed — "
                        "rootkit detection may be impaired\n");
    }
#endif

    s_initialized = true;
    return true;
}

// ============================================================================
// AsmCore::HasSSE2Support / HasSSE41Support
// Uses CPUID instruction to detect processor features
// ============================================================================
bool AsmCore::HasSSE2Support() {
    int cpuid_result[4] = {};

#ifdef _WIN32
    __cpuid(cpuid_result, 1);
#else
    __cpuid(1, cpuid_result[0], cpuid_result[1], cpuid_result[2], cpuid_result[3]);
#endif

    // ECX bit 26 = SSE4.1, EDX bit 26 = SSE2
    return (cpuid_result[3] & (1 << 26)) != 0;
}

bool AsmCore::HasSSE41Support() {
    int cpuid_result[4] = {};

#ifdef _WIN32
    __cpuid(cpuid_result, 1);
#else
    __cpuid(1, cpuid_result[0], cpuid_result[1], cpuid_result[2], cpuid_result[3]);
#endif

    return (cpuid_result[2] & (1 << 19)) != 0;
}

// ============================================================================
// AsmCore::FormatMD5Hex
// Converts 16-byte MD5 digest to 32-char lowercase hex string
// ============================================================================
void AsmCore::FormatMD5Hex(const uint8_t* digest, char* hex_out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 16; ++i) {
        hex_out[i * 2]     = hex_chars[(digest[i] >> 4) & 0x0F];
        hex_out[i * 2 + 1] = hex_chars[digest[i] & 0x0F];
    }
    hex_out[32] = '\0';
}

// ============================================================================
// AsmCore::ComputeFileMD5
// Memory-maps the file, calls AsmMD5Compute, formats hex string
// ============================================================================
bool AsmCore::ComputeFileMD5(const char* file_path, AsmMD5Result& result_out) {
    memset(&result_out, 0, sizeof(result_out));

    const uint8_t* mapped_data = nullptr;
    uint64_t file_size = 0;

#ifdef _WIN32
    // Windows: memory-map the file
    HANDLE hFile = CreateFileA(
        file_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER li_size;
    if (!GetFileSizeEx(hFile, &li_size)) {
        CloseHandle(hFile);
        return false;
    }
    file_size = static_cast<uint64_t>(li_size.QuadPart);

    if (file_size == 0) {
        // MD5 of empty file is well-defined
        CloseHandle(hFile);
        // d41d8cd98f00b204e9800998ecf8427e
        memcpy(result_out.hex, "d41d8cd98f00b204e9800998ecf8427e", 33);
        result_out.computed = true;
        return true;
    }

    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) {
        CloseHandle(hFile);
        return false;
    }

    mapped_data = static_cast<const uint8_t*>(
        MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0)
    );

    if (!mapped_data) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

#else
    // Linux: mmap the file
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }

    file_size = static_cast<uint64_t>(st.st_size);

    if (file_size == 0) {
        close(fd);
        memcpy(result_out.hex, "d41d8cd98f00b204e9800998ecf8427e", 33);
        result_out.computed = true;
        return true;
    }

    void* mmap_ptr = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (mmap_ptr == MAP_FAILED) return false;

    // Advise kernel we'll read sequentially
    madvise(mmap_ptr, file_size, MADV_SEQUENTIAL);

    mapped_data = static_cast<const uint8_t*>(mmap_ptr);
#endif

    // Call NASM MD5 engine
    int ret = AsmMD5Compute(mapped_data, file_size, result_out.digest);

#ifdef _WIN32
    UnmapViewOfFile(mapped_data);
    CloseHandle(hMap);
    CloseHandle(hFile);
#else
    munmap(const_cast<uint8_t*>(mapped_data), file_size);
#endif

    if (ret != 0) return false;

    FormatMD5Hex(result_out.digest, result_out.hex);
    result_out.computed = true;
    return true;
}

// ============================================================================
// AsmCore::ComputeFileEntropy
// Memory-maps the file, calls AsmEntropyCalc with full histogram
// ============================================================================
bool AsmCore::ComputeFileEntropy(const char* file_path, AsmEntropyResult& result_out) {
    memset(&result_out, 0, sizeof(result_out));

    const uint8_t* mapped_data = nullptr;
    uint64_t file_size = 0;
    bool success = false;

#ifdef _WIN32
    HANDLE hFile = CreateFileA(file_path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER li_size;
    GetFileSizeEx(hFile, &li_size);
    file_size = static_cast<uint64_t>(li_size.QuadPart);

    if (file_size == 0) {
        CloseHandle(hFile);
        result_out.value = 0.0;
        result_out.classification = 0;
        return true;
    }

    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    mapped_data = static_cast<const uint8_t*>(
        MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));

    if (!mapped_data) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }
#else
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    fstat(fd, &st);
    file_size = static_cast<uint64_t>(st.st_size);

    if (file_size == 0) {
        close(fd);
        return true;
    }

    void* mmap_ptr = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (mmap_ptr == MAP_FAILED) return false;
    mapped_data = static_cast<const uint8_t*>(mmap_ptr);
#endif

    // Call ASM entropy engine
    result_out.classification = static_cast<uint32_t>(
        AsmEntropyCalc(mapped_data, file_size, &result_out.value)
    );

    // Grab the histogram for visualization
    uint32_t* hist = AsmEntropyGetHistogram();
    if (hist) {
        memcpy(result_out.histogram, hist, 256 * sizeof(uint32_t));
    }

    success = true;

#ifdef _WIN32
    UnmapViewOfFile(mapped_data);
    CloseHandle(hMap);
    CloseHandle(hFile);
#else
    munmap(const_cast<uint8_t*>(mapped_data), file_size);
#endif

    return success;
}

} // namespace PhantomScope
