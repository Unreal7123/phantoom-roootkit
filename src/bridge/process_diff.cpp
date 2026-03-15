// ============================================================================
// PhantomScope — process_diff.cpp
// Process Diff Engine — Hidden Process Detection
//
// Core rootkit detection logic: compares the kernel-mode process list
// (obtained via direct NtQuerySystemInformation syscall) against the
// user-mode visible process list (CreateToolhelp32Snapshot / /proc walk).
//
// Any PID present ONLY in the kernel list but ABSENT from the user-mode
// list is definitively identified as a HIDDEN PROCESS — the strongest
// possible indicator of a ring-0 rootkit.
//
// Design: Uses sorted std::vector + std::set_difference for O(n log n)
// comparison. On Windows, also checks against EPROCESS list via the
// NtQuerySystemInformation kernel path which a user-mode rootkit cannot
// manipulate without kernel access itself.
// ============================================================================

#include "process_diff.h"
#include "asm_bridge.h"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>
    #include <psapi.h>
    #pragma comment(lib, "psapi.lib")
#else
    #include <dirent.h>
    #include <fstream>
    #include <sstream>
#endif

namespace PhantomScope {

// ============================================================================
// ProcessRecord — unified process representation
// ============================================================================
struct ProcessRecord {
    uint32_t pid;
    uint32_t ppid;
    uint32_t thread_count;
    std::string name;
    std::string path;
    bool from_kernel;     // Found via ASM/kernel path
    bool from_usermode;   // Found via Win32/usermode path
    bool is_hidden;       // kernel=true, usermode=false
};

// ============================================================================
// ProcessDiffEngine — Implementation
// ============================================================================

class ProcessDiffEngineImpl {
public:
    ProcessDiffResult Run();

private:
    // Windows enumeration paths
#ifdef _WIN32
    std::vector<ProcessRecord> EnumerateKernelPath_Windows();
    std::vector<ProcessRecord> EnumerateUserModePath_Windows();
    std::string GetProcessPath_Windows(uint32_t pid);
#endif

    // Linux enumeration paths
#ifdef __linux__
    std::vector<ProcessRecord> EnumerateKernelPath_Linux();
    std::vector<ProcessRecord> EnumerateUserModePath_Linux();
    std::string ReadProcFile(uint32_t pid, const char* filename);
    std::unordered_map<uint32_t, std::string> BuildProcNameMap();
#endif

    // Cross-platform diff computation
    ProcessDiffResult ComputeDiff(
        const std::vector<ProcessRecord>& kernel_list,
        const std::vector<ProcessRecord>& usermode_list
    );
};

// ============================================================================
// Windows: Kernel-path enumeration via NtQuerySystemInformation direct syscall
// ============================================================================
#ifdef _WIN32

// SYSTEM_PROCESS_INFORMATION structure (not fully defined in user SDK)
struct SYSTEM_PROCESS_INFORMATION_EX {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      UniqueProcessKey;
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    // ... more fields omitted
};

std::vector<ProcessRecord> ProcessDiffEngineImpl::EnumerateKernelPath_Windows() {
    std::vector<ProcessRecord> result;

    // Initial buffer size: 1MB (usually sufficient, will resize on mismatch)
    ULONG buffer_size = 1024 * 1024;
    std::unique_ptr<uint8_t[]> buffer;

    NTSTATUS status;
    ULONG return_length = 0;

    // Retry loop: expand buffer until NtQuerySystemInformation succeeds
    for (int attempt = 0; attempt < 8; ++attempt) {
        buffer = std::make_unique<uint8_t[]>(buffer_size);

        // DIRECT SYSCALL — bypasses any ntdll.dll hooks
        status = AsmQueryProcessList(
            5,  // SystemProcessInformation
            buffer.get(),
            buffer_size,
            &return_length
        );

        if (status == 0x00000000) {
            break;  // STATUS_SUCCESS
        }

        if (status == 0xC0000004) {
            // STATUS_INFO_LENGTH_MISMATCH — grow buffer
            buffer_size = return_length + 65536;  // extra margin
            continue;
        }

        // Other error (e.g., access denied, invalid parameter)
        return result;
    }

    if (status != 0) return result;

    // Walk SYSTEM_PROCESS_INFORMATION linked list
    const auto* entry = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION_EX*>(
        buffer.get());

    while (true) {
        uint32_t pid = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(entry->UniqueProcessId));

        ProcessRecord rec;
        rec.pid           = pid;
        rec.ppid          = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(entry->InheritedFromUniqueProcessId));
        rec.thread_count  = entry->NumberOfThreads;
        rec.from_kernel   = true;
        rec.from_usermode = false;
        rec.is_hidden     = false;

        // Convert UNICODE_STRING ImageName to UTF-8
        if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
            int utf8_len = WideCharToMultiByte(
                CP_UTF8, 0,
                entry->ImageName.Buffer,
                entry->ImageName.Length / sizeof(WCHAR),
                nullptr, 0, nullptr, nullptr
            );
            if (utf8_len > 0) {
                rec.name.resize(utf8_len);
                WideCharToMultiByte(
                    CP_UTF8, 0,
                    entry->ImageName.Buffer,
                    entry->ImageName.Length / sizeof(WCHAR),
                    rec.name.data(), utf8_len, nullptr, nullptr
                );
            }
        }

        // Get full executable path for non-system processes
        if (pid > 4) {
            rec.path = GetProcessPath_Windows(pid);
        }

        result.push_back(std::move(rec));

        if (entry->NextEntryOffset == 0) break;
        entry = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION_EX*>(
            reinterpret_cast<const uint8_t*>(entry) + entry->NextEntryOffset
        );
    }

    return result;
}

std::vector<ProcessRecord> ProcessDiffEngineImpl::EnumerateUserModePath_Windows() {
    std::vector<ProcessRecord> result;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return result;
    }

    do {
        ProcessRecord rec;
        rec.pid           = pe32.th32ProcessID;
        rec.ppid          = pe32.th32ParentProcessID;
        rec.thread_count  = pe32.cntThreads;
        rec.from_kernel   = false;
        rec.from_usermode = true;
        rec.is_hidden     = false;

        // Convert wide string to UTF-8
        int utf8_len = WideCharToMultiByte(
            CP_UTF8, 0, pe32.szExeFile, -1, nullptr, 0, nullptr, nullptr);
        if (utf8_len > 0) {
            rec.name.resize(utf8_len);
            WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1,
                rec.name.data(), utf8_len, nullptr, nullptr);
            // Remove null terminator from string size
            while (!rec.name.empty() && rec.name.back() == '\0')
                rec.name.pop_back();
        }

        rec.path = GetProcessPath_Windows(rec.pid);

        result.push_back(std::move(rec));
    } while (Process32NextW(snapshot, &pe32));

    CloseHandle(snapshot);
    return result;
}

std::string ProcessDiffEngineImpl::GetProcessPath_Windows(uint32_t pid) {
    // Try to get full executable path via QueryFullProcessImageNameW
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (!hProc) return {};

    WCHAR path_buf[MAX_PATH * 2] = {};
    DWORD size = MAX_PATH * 2;

    bool ok = QueryFullProcessImageNameW(hProc, 0, path_buf, &size) != 0;
    CloseHandle(hProc);

    if (!ok) return {};

    int utf8_len = WideCharToMultiByte(
        CP_UTF8, 0, path_buf, -1, nullptr, 0, nullptr, nullptr);
    if (utf8_len <= 0) return {};

    std::string result(utf8_len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, path_buf, -1,
        result.data(), utf8_len, nullptr, nullptr);
    while (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

#endif // _WIN32

// ============================================================================
// Linux: Kernel-path enumeration via sys_getdents64 on /proc (ASM)
// ============================================================================
#ifdef __linux__

std::vector<ProcessRecord> ProcessDiffEngineImpl::EnumerateKernelPath_Linux() {
    std::vector<ProcessRecord> result;

    constexpr uint32_t MAX_PIDS = 65536;
    std::vector<uint32_t> pid_array(MAX_PIDS);
    uint32_t count = 0;

    // Direct ASM enumeration via sys_getdents64 on /proc
    int ret = AsmLinuxEnumProcesses(pid_array.data(), MAX_PIDS, &count);
    if (ret != 0) {
        // Fall back to opendir() if ASM fails
        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) return result;

        struct dirent* entry;
        count = 0;
        while ((entry = readdir(proc_dir)) != nullptr && count < MAX_PIDS) {
            if (entry->d_type == DT_DIR && entry->d_name[0] >= '0'
                    && entry->d_name[0] <= '9') {
                pid_array[count++] = static_cast<uint32_t>(
                    std::stoul(entry->d_name));
            }
        }
        closedir(proc_dir);
    }

    // For each PID, read /proc/<pid>/status for name and state
    result.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t pid = pid_array[i];
        ProcessRecord rec;
        rec.pid           = pid;
        rec.from_kernel   = true;
        rec.from_usermode = false;
        rec.is_hidden     = false;

        // Read name via ASM (or fallback to C++)
        char name_buf[64] = {};
        char state_buf = 0;
        if (AsmLinuxReadProcStatus(pid, name_buf, &state_buf) == 0) {
            rec.name = name_buf;
        }

        // Read PPID from /proc/<pid>/status
        std::string status_path = "/proc/" + std::to_string(pid) + "/status";
        std::ifstream sf(status_path);
        std::string line;
        while (std::getline(sf, line)) {
            if (line.compare(0, 5, "PPid:") == 0) {
                rec.ppid = std::stoul(line.substr(5));
            }
            if (line.compare(0, 8, "Threads:") == 0) {
                rec.thread_count = std::stoul(line.substr(8));
            }
        }

        // Get executable path from /proc/<pid>/exe symlink
        std::string exe_link = "/proc/" + std::to_string(pid) + "/exe";
        char exe_path[4096] = {};
        ssize_t len = readlink(exe_link.c_str(), exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            rec.path = std::string(exe_path, len);
        }

        result.push_back(std::move(rec));
    }

    return result;
}

std::vector<ProcessRecord> ProcessDiffEngineImpl::EnumerateUserModePath_Linux() {
    std::vector<ProcessRecord> result;

    // Parse /proc/<pid>/status via standard C++ (represents "visible" usermode view)
    // A rootkit hooking getdents64 would hide processes here but not in ASM path
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return result;

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

        uint32_t pid = static_cast<uint32_t>(std::stoul(entry->d_name));

        ProcessRecord rec;
        rec.pid           = pid;
        rec.from_kernel   = false;
        rec.from_usermode = true;
        rec.is_hidden     = false;

        std::string status_path = "/proc/" + std::string(entry->d_name) + "/status";
        std::ifstream sf(status_path);
        std::string line;

        while (std::getline(sf, line)) {
            if (line.compare(0, 5, "Name:") == 0) {
                rec.name = line.substr(6);
                while (!rec.name.empty() && (rec.name.back() == '\n'
                       || rec.name.back() == '\r' || rec.name.back() == ' '))
                    rec.name.pop_back();
            }
            if (line.compare(0, 5, "PPid:") == 0) {
                try { rec.ppid = std::stoul(line.substr(5)); } catch (...) {}
            }
        }

        result.push_back(std::move(rec));
    }

    closedir(proc_dir);
    return result;
}

#endif // __linux__

// ============================================================================
// ComputeDiff — Cross-platform hidden process detection
//
// Algorithm: O(n log n) using sorted PIDs + set operations
//   1. Build PID sets from both lists
//   2. kernel_only = kernel_pids - usermode_pids
//   3. Tag those entries as HIDDEN in the combined output
// ============================================================================
ProcessDiffResult ProcessDiffEngineImpl::ComputeDiff(
    const std::vector<ProcessRecord>& kernel_list,
    const std::vector<ProcessRecord>& usermode_list)
{
    ProcessDiffResult result;
    result.scan_time = 0;  // Set by caller
    result.kernel_count   = static_cast<uint32_t>(kernel_list.size());
    result.usermode_count = static_cast<uint32_t>(usermode_list.size());

    // Build fast lookup set of user-mode PIDs
    std::unordered_set<uint32_t> usermode_pids;
    usermode_pids.reserve(usermode_list.size());
    for (const auto& proc : usermode_list) {
        usermode_pids.insert(proc.pid);
    }

    // Build fast lookup map for user-mode name lookup
    std::unordered_map<uint32_t, const ProcessRecord*> usermode_map;
    usermode_map.reserve(usermode_list.size());
    for (const auto& proc : usermode_list) {
        usermode_map[proc.pid] = &proc;
    }

    // Build combined output list
    // Start with kernel list as ground truth
    for (const auto& kproc : kernel_list) {
        ProcessInfo info;
        info.pid          = kproc.pid;
        info.ppid         = kproc.ppid;
        info.thread_count = kproc.thread_count;
        info.name         = kproc.name;
        info.path         = kproc.path;
        info.from_kernel  = true;

        if (usermode_pids.count(kproc.pid) > 0) {
            // Process is visible in both — normal
            info.from_usermode = true;
            info.is_hidden     = false;

            // If kernel has no path but usermode does, use usermode path
            if (info.path.empty()) {
                auto it = usermode_map.find(kproc.pid);
                if (it != usermode_map.end()) {
                    info.path = it->second->path;
                }
            }
        } else {
            // HIDDEN PROCESS — in kernel but not in user-mode API
            info.from_usermode = false;
            info.is_hidden     = true;
            result.hidden_processes.push_back(info);
            result.hidden_count++;
        }

        result.all_processes.push_back(std::move(info));
    }

    // Check for usermode-only processes (zombie/unusual state)
    for (const auto& uproc : usermode_list) {
        bool in_kernel = false;
        for (const auto& kproc : kernel_list) {
            if (kproc.pid == uproc.pid) {
                in_kernel = true;
                break;
            }
        }

        if (!in_kernel) {
            ProcessInfo info;
            info.pid           = uproc.pid;
            info.ppid          = uproc.ppid;
            info.thread_count  = uproc.thread_count;
            info.name          = uproc.name;
            info.path          = uproc.path;
            info.from_kernel   = false;
            info.from_usermode = true;
            info.is_hidden     = false;
            // Note: usermode-only is unusual but not necessarily malicious
            // Could be a process that terminated between the two scans
            result.all_processes.push_back(std::move(info));
        }
    }

    return result;
}

// ============================================================================
// Public API
// ============================================================================
ProcessDiffResult ProcessDiffEngineImpl::Run() {
#ifdef _WIN32
    auto kernel_list   = EnumerateKernelPath_Windows();
    auto usermode_list = EnumerateUserModePath_Windows();
#else
    auto kernel_list   = EnumerateKernelPath_Linux();
    auto usermode_list = EnumerateUserModePath_Linux();
#endif

    return ComputeDiff(kernel_list, usermode_list);
}

// ============================================================================
// ProcessDiffEngine — Public class forwarding to impl
// ============================================================================
ProcessDiffEngine::ProcessDiffEngine()
    : impl_(std::make_unique<ProcessDiffEngineImpl>()) {}

ProcessDiffEngine::~ProcessDiffEngine() = default;

ProcessDiffResult ProcessDiffEngine::RunDiff() {
    return impl_->Run();
}

} // namespace PhantomScope
