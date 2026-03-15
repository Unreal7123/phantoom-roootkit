#pragma once
// ============================================================================
// PhantomScope — process_diff.h
// Process Diff Engine Header
// ============================================================================

#ifndef PHANTOMSCOPE_PROCESS_DIFF_H
#define PHANTOMSCOPE_PROCESS_DIFF_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace PhantomScope {

struct ProcessInfo {
    uint32_t    pid;
    uint32_t    ppid;
    uint32_t    thread_count;
    std::string name;
    std::string path;
    bool        from_kernel;
    bool        from_usermode;
    bool        is_hidden;       // true = rootkit indicator
    double      entropy;         // filled by file scanner
    std::string md5;             // filled by file scanner
    int32_t     vt_detections;   // -1 = not checked
    std::string threat_family;
    uint32_t    threat_score;    // 0-100
};

struct ProcessDiffResult {
    std::vector<ProcessInfo> all_processes;
    std::vector<ProcessInfo> hidden_processes;
    uint32_t kernel_count;
    uint32_t usermode_count;
    uint32_t hidden_count;
    uint64_t scan_time;
    bool     success;
};

class ProcessDiffEngineImpl;

class ProcessDiffEngine {
public:
    ProcessDiffEngine();
    ~ProcessDiffEngine();

    ProcessDiffResult RunDiff();

private:
    std::unique_ptr<ProcessDiffEngineImpl> impl_;
};

} // namespace PhantomScope

#endif // PHANTOMSCOPE_PROCESS_DIFF_H
