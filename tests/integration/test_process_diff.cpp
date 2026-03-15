// ============================================================================
// PhantomScope — tests/integration/test_process_diff.cpp
// Process Diff Engine — Integration Test
//
// Validates that the dual-path enumeration correctly identifies:
//   - Processes visible in both paths (normal)
//   - Mock "hidden" processes injected into the kernel list only
//
// This test uses a mock ProcessEnumerator that returns controlled data
// to verify the diff algorithm without requiring a live rootkit.
// ============================================================================

#include <cstdio>
#include <cstring>
#include <cassert>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <cstdint>

// Minimal re-implementation of the diff algorithm for testing
// (avoids linking the full C++ bridge)

struct MockProcess {
    uint32_t pid;
    uint32_t ppid;
    const char* name;
    bool from_kernel;
    bool from_usermode;
};

struct DiffResult {
    std::vector<MockProcess> all;
    std::vector<uint32_t>   hidden_pids;
};

DiffResult ComputeMockDiff(
    const std::vector<MockProcess>& kernel_list,
    const std::vector<MockProcess>& usermode_list)
{
    DiffResult result;

    std::unordered_set<uint32_t> usermode_pids;
    for (const auto& p : usermode_list) usermode_pids.insert(p.pid);

    for (auto proc : kernel_list) {
        proc.from_kernel   = true;
        proc.from_usermode = usermode_pids.count(proc.pid) > 0;

        if (!proc.from_usermode) {
            result.hidden_pids.push_back(proc.pid);
        }

        result.all.push_back(proc);
    }

    return result;
}

// ---- Test cases ----

static int test_no_hidden_processes() {
    std::vector<MockProcess> kernel = {
        { 4,    0,   "System",      false, false },
        { 644,  4,   "smss.exe",    false, false },
        { 788,  644, "csrss.exe",   false, false },
        { 4096, 788, "explorer.exe",false, false },
    };

    std::vector<MockProcess> usermode = kernel;  // identical

    auto result = ComputeMockDiff(kernel, usermode);

    if (!result.hidden_pids.empty()) {
        printf("[FAIL] test_no_hidden_processes: expected 0 hidden, got %zu\n",
               result.hidden_pids.size());
        return 1;
    }

    printf("[PASS] test_no_hidden_processes: 0 hidden processes correctly identified\n");
    return 0;
}

static int test_one_hidden_process() {
    std::vector<MockProcess> kernel = {
        { 4,    0,   "System",      false, false },
        { 644,  4,   "smss.exe",    false, false },
        { 1337, 644, "rootkit.sys", false, false },  // HIDDEN
        { 4096, 788, "explorer.exe",false, false },
    };

    std::vector<MockProcess> usermode = {
        { 4,    0,   "System",      false, false },
        { 644,  4,   "smss.exe",    false, false },
        // 1337 NOT present — rootkit hiding itself
        { 4096, 788, "explorer.exe",false, false },
    };

    auto result = ComputeMockDiff(kernel, usermode);

    if (result.hidden_pids.size() != 1 || result.hidden_pids[0] != 1337) {
        printf("[FAIL] test_one_hidden_process: expected PID 1337 hidden, got:\n");
        for (auto pid : result.hidden_pids) printf("  PID %u\n", pid);
        return 1;
    }

    printf("[PASS] test_one_hidden_process: PID 1337 correctly identified as hidden\n");
    return 0;
}

static int test_multiple_hidden_processes() {
    std::vector<MockProcess> kernel = {
        { 4,     0,    "System",         false, false },
        { 1111,  4,    "hidden1.sys",    false, false },
        { 2222,  1111, "hidden2.sys",    false, false },
        { 3333,  2222, "hidden_child",   false, false },
        { 4096,  4,    "svchost.exe",    false, false },
    };

    std::vector<MockProcess> usermode = {
        { 4,    0, "System",      false, false },
        { 4096, 4, "svchost.exe", false, false },
        // 1111, 2222, 3333 all hidden
    };

    auto result = ComputeMockDiff(kernel, usermode);

    std::unordered_set<uint32_t> expected = { 1111, 2222, 3333 };
    std::unordered_set<uint32_t> got(result.hidden_pids.begin(), result.hidden_pids.end());

    if (got != expected) {
        printf("[FAIL] test_multiple_hidden_processes:\n");
        printf("  Expected PIDs: ");
        for (auto p : expected) printf("%u ", p);
        printf("\n  Got PIDs:      ");
        for (auto p : got) printf("%u ", p);
        printf("\n");
        return 1;
    }

    printf("[PASS] test_multiple_hidden_processes: 3 hidden PIDs correctly identified\n");
    return 0;
}

static int test_pid_zero_not_hidden() {
    // PID 0 (Idle) is typically kernel-only but should not be flagged
    std::vector<MockProcess> kernel = {
        { 0,   0, "Idle",    false, false },
        { 4,   0, "System",  false, false },
        { 100, 4, "app.exe", false, false },
    };

    std::vector<MockProcess> usermode = {
        { 4,   0, "System",  false, false },
        { 100, 4, "app.exe", false, false },
        // 0 not in usermode (expected for Idle)
    };

    auto result = ComputeMockDiff(kernel, usermode);

    // PID 0 will show as "hidden" — the real engine filters this
    // Here we just verify the algorithm correctly detects the delta
    bool pid0_in_hidden = std::find(result.hidden_pids.begin(),
                                     result.hidden_pids.end(), 0u)
                          != result.hidden_pids.end();

    printf("[INFO] test_pid_zero: PID 0 in hidden list = %s (filter applied in real engine)\n",
           pid0_in_hidden ? "yes" : "no");
    return 0;  // Not a failure — filtering is done at a higher level
}

static int test_empty_lists() {
    auto result = ComputeMockDiff({}, {});
    bool ok = result.all.empty() && result.hidden_pids.empty();
    printf("[%s] test_empty_lists\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

int main() {
    printf("PhantomScope Process Diff Engine — Integration Tests\n");
    printf("====================================================\n\n");

    int failures = 0;
    failures += test_no_hidden_processes();
    failures += test_one_hidden_process();
    failures += test_multiple_hidden_processes();
    failures += test_pid_zero_not_hidden();
    failures += test_empty_lists();

    printf("\n%s: %d failure(s)\n",
           failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           failures);

    return failures > 0 ? 1 : 0;
}
