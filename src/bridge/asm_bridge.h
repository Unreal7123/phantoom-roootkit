#pragma once
// ============================================================================
// PhantomScope — asm_bridge.h
// C++ ↔ NASM Assembly FFI Interface
//
// All functions declared here are implemented in the NASM .asm modules and
// exported via extern "C" to prevent C++ name mangling. The C++ bridge
// layer links against the compiled NASM objects and calls through this
// header to invoke the assembly performance core.
//
// Design principle: The assembly modules know nothing about C++ — they
// operate on raw pointers and primitive types only. All memory allocation,
// error handling, and type marshaling is the responsibility of C++.
// ============================================================================

#ifndef PHANTOMSCOPE_ASM_BRIDGE_H
#define PHANTOMSCOPE_ASM_BRIDGE_H

#include <cstdint>
#include <cstddef>

#ifdef _WIN32
    #include <windows.h>
    #define PS_API __cdecl
#else
    #include <sys/types.h>
    #define PS_API
    // Windows type aliases for cross-platform compatibility
    using NTSTATUS = int32_t;
    using ULONG    = uint32_t;
    using PVOID    = void*;
    using PULONG   = uint32_t*;
    using HANDLE   = void*;
#endif

// ============================================================================
// STATUS CODES
// ============================================================================
#define PS_SUCCESS              0
#define PS_ERROR_BUFFER_SMALL   0xC0000004  // STATUS_INFO_LENGTH_MISMATCH
#define PS_ERROR_ACCESS_DENIED  0xC0000022
#define PS_ERROR_NOT_FOUND      0xFFFFFFFF
#define PS_SSN_UNRESOLVED       0xFFFFFFFF

// ============================================================================
// ENTROPY CLASSIFICATION
// ============================================================================
enum class EntropyClass : uint32_t {
    Clean      = 0,  // entropy <= 6.5 — normal content
    Suspicious = 1,  // entropy 6.5-7.5 — likely packed/compressed
    Encrypted  = 2   // entropy > 7.5 — almost certainly encrypted
};

// ============================================================================
// PROCESS INFO STRUCTURES
// ============================================================================

#pragma pack(push, 1)

// Compact process record returned by ASM enumeration
struct AsmProcessEntry {
    uint32_t pid;
    uint32_t ppid;
    uint32_t thread_count;
    uint32_t _pad;
    uint64_t create_time;        // FILETIME on Windows, unix timestamp on Linux
    char     name[260];          // Process image name (UTF-8 on Linux, converted from UNICODE on Windows)
    char     path[1024];         // Full image path
    bool     is_hidden;          // Set by process_diff.cpp, not by ASM
    bool     is_kernel_only;     // Present in kernel list, absent from usermode
};

// Output buffer header for AsmQueryProcessList
struct AsmProcessListHeader {
    uint32_t count;              // Number of entries
    uint32_t capacity;           // Max entries buffer can hold
    uint32_t bytes_needed;       // Set on STATUS_INFO_LENGTH_MISMATCH
    uint32_t _pad;
    AsmProcessEntry entries[1];  // Variable length array
};

// Entropy analysis result
struct AsmEntropyResult {
    double   value;              // Shannon entropy (0.0 - 8.0)
    uint32_t classification;     // 0=clean, 1=suspicious, 2=encrypted
    uint32_t histogram[256];     // Byte frequency histogram
};

// MD5 digest result
struct AsmMD5Result {
    uint8_t  digest[16];         // Raw 16-byte MD5 digest
    char     hex[33];            // Null-terminated 32-char hex string
    bool     computed;           // True if computation succeeded
};

// SSN resolution result
struct AsmSSNResult {
    uint32_t ssn;                // System Service Number
    bool     resolved;           // True if found and not hooked
    bool     was_hooked;         // True if function was hooked (fallback used)
    char     func_name[64];      // Function name
};

#pragma pack(pop)

// ============================================================================
// EXTERN "C" — NASM EXPORTED FUNCTIONS
// ============================================================================

extern "C" {

// ---- process_enum.asm (Windows only) ----
#ifdef _WIN32

/**
 * Direct syscall to NtQuerySystemInformation.
 * Bypasses all user-mode hooks in ntdll.dll.
 *
 * @param SystemInformationClass 5 = SystemProcessInformation
 * @param SystemInformation      Output buffer
 * @param SystemInformationLength Buffer size in bytes
 * @param ReturnLength           Bytes written (or needed on error)
 * @return NTSTATUS
 */
NTSTATUS PS_API AsmQueryProcessList(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

/**
 * NtOpenProcess direct syscall — bypasses AV/EDR hooks.
 * @return NTSTATUS
 */
NTSTATUS PS_API AsmOpenProcessDirect(
    HANDLE* ProcessHandle,
    uint32_t DesiredAccess,
    void*   ObjectAttributes,
    void*   ClientId          // PCLIENT_ID { PVOID UniqueProcess, PVOID UniqueThread }
);

/**
 * NtClose direct syscall.
 */
NTSTATUS PS_API AsmCloseHandleDirect(HANDLE handle);

/**
 * Get/set the resolved SSN for NtQuerySystemInformation.
 * Called by syscall_wrapper after dynamic resolution.
 */
uint32_t PS_API AsmGetSSN_NtQuerySysInfo(void);
void     PS_API AsmSetSSN_NtQuerySysInfo(uint32_t ssn);

#endif // _WIN32

// ---- syscall_wrapper.asm (Windows only) ----
#ifdef _WIN32

/**
 * Resolves all required SSNs by walking ntdll's export table.
 * Must be called once at startup before any direct syscalls.
 * @return Number of successfully resolved SSNs (0 = critical failure)
 */
int PS_API AsmResolveAllSSNs(void);

/**
 * Resolves SSN for a single named NT function.
 * @param func_name Null-terminated function name (e.g., "NtQuerySystemInformation")
 * @return SSN, or PS_SSN_UNRESOLVED on failure
 */
uint32_t PS_API AsmResolveSSN(const char* func_name);

/**
 * Returns ntdll.dll base address from PEB walk.
 * @return Base address or NULL
 */
void* PS_API AsmGetNtdllBase(void);

/**
 * Generic syscall stub — useful for NT functions not enumerated above.
 * @param ssn    The resolved System Service Number
 * @param arg1..n Arguments to pass in registers
 * @return NTSTATUS
 */
NTSTATUS PS_API AsmGenericSyscall(uint32_t ssn, ...);

/**
 * Returns cached resolved SSN by index.
 * Index: 0=NtQuerySysInfo, 1=NtOpenProcess, 2=NtClose
 */
uint32_t PS_API AsmGetResolvedSSN(uint32_t index);

#endif // _WIN32

// ---- linux_proc.asm (Linux only) ----
#ifdef __linux__

/**
 * Enumerates all processes via sys_getdents64 on /proc.
 * @param pid_array  Output array of PIDs
 * @param capacity   Max PIDs to return
 * @param count_out  Actual number of PIDs found
 * @return 0 on success, -errno on failure
 */
int PS_API AsmLinuxEnumProcesses(
    uint32_t* pid_array,
    uint32_t  capacity,
    uint32_t* count_out
);

/**
 * Reads Name and State from /proc/<pid>/status.
 * @param pid          Process ID
 * @param name_out     Output buffer for process name (64 bytes)
 * @param state_out    Output byte for state character
 * @return 0 on success, -1 on failure
 */
int PS_API AsmLinuxReadProcStatus(
    uint32_t pid,
    char*    name_out,
    char*    state_out
);

#endif // __linux__

// ---- md5_engine.asm (Cross-platform) ----

/**
 * Computes MD5 digest of a memory region.
 * @param data     Pointer to data (memory-mapped file view)
 * @param length   Data length in bytes
 * @param output   Output buffer (must be >= 16 bytes)
 * @return 0 on success, non-zero on error
 */
int PS_API AsmMD5Compute(
    const uint8_t* data,
    uint64_t       length,
    uint8_t*       output
);

/**
 * Initialize MD5 state (call before AsmMD5Update).
 */
void PS_API AsmMD5Init(void);

/**
 * Update MD5 state with a data chunk (streaming interface).
 * @param chunk  Data chunk pointer
 * @param length Chunk length in bytes
 */
void PS_API AsmMD5Update(const uint8_t* chunk, uint64_t length);

/**
 * Finalize MD5 computation and write digest.
 * @param output 16-byte output buffer
 */
void PS_API AsmMD5Final(uint8_t* output);

// ---- entropy_calc.asm (Cross-platform) ----

/**
 * Computes Shannon entropy for a memory region.
 * @param data     Data pointer
 * @param length   Data length in bytes
 * @param entropy_out If non-NULL, receives the actual entropy value (double)
 * @return 0 (clean), 1 (suspicious >6.5), 2 (encrypted >7.5)
 */
int PS_API AsmEntropyCalc(
    const uint8_t* data,
    uint64_t       length,
    double*        entropy_out
);

/**
 * Computes entropy for a specific binary section.
 * @param section_data  Section data pointer
 * @param section_size  Section size in bytes
 * @param section_name  Section name (8 bytes, null-padded)
 * @param result_out    Output: { double entropy, uint32_t classification }
 */
void PS_API AsmEntropyCalcSection(
    const uint8_t* section_data,
    uint64_t       section_size,
    const char*    section_name,
    AsmEntropyResult* result_out
);

/**
 * Builds byte frequency histogram using SSE4.1 SIMD.
 * @param data     Data pointer
 * @param length   Data length
 */
void PS_API AsmBuildHistogramSIMD(const uint8_t* data, uint64_t length);

/**
 * Computes entropy from the internal histogram (call after AsmBuildHistogramSIMD).
 * @return Classification: 0/1/2 (clean/suspicious/encrypted)
 */
int PS_API AsmComputeEntropyFromHistogram(void);

/**
 * Returns pointer to the internal 256-entry histogram array.
 * Array contains uint32_t frequency counts for each byte value 0-255.
 */
uint32_t* PS_API AsmEntropyGetHistogram(void);

} // extern "C"

// ============================================================================
// C++ WRAPPER CLASS — Convenience interface over raw ASM exports
// ============================================================================

namespace PhantomScope {

class AsmCore {
public:
    /**
     * Initialize the assembly core — resolves SSNs, verifies CPU feature support.
     * Must be called once at application startup.
     * @return true on success
     */
    static bool Initialize();

    /**
     * Compute MD5 of a file (using memory-mapped I/O internally).
     * @param file_path  Path to file
     * @param result_out Output MD5 result struct
     * @return true on success
     */
    static bool ComputeFileMD5(const char* file_path, AsmMD5Result& result_out);

    /**
     * Compute Shannon entropy of a file.
     * @param file_path    Path to file
     * @param result_out   Output entropy result struct
     * @return true on success
     */
    static bool ComputeFileEntropy(const char* file_path, AsmEntropyResult& result_out);

    /**
     * Check SSE4.1 support (required for SIMD histogram).
     * Falls back to scalar path if not available.
     */
    static bool HasSSE41Support();
    static bool HasSSE2Support();

private:
    static bool s_initialized;
    static bool s_sse41_available;
    static bool s_sse2_available;

    // Utility: format raw MD5 bytes as hex string
    static void FormatMD5Hex(const uint8_t* digest, char* hex_out);
};

} // namespace PhantomScope

#endif // PHANTOMSCOPE_ASM_BRIDGE_H
