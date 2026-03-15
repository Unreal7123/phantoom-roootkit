# PhantomScope — CHANGELOG.md

# Changelog

All notable changes to PhantomScope are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — March 2026

### Added

#### Assembly Core (Tier 1)
- `process_enum.asm` — `NtQuerySystemInformation(SystemProcessInformation)` direct syscall stub bypassing all ntdll.dll hooks
- `syscall_wrapper.asm` — "Hell's Gate" dynamic SSN resolution by walking the ntdll export table at runtime; validates non-hooked function prologue (4C 8B D1 B8 pattern)
- `md5_engine.asm` — Full RFC 1321 MD5 in pure NASM x86-64 with SSE2 round function optimization and memory-mapped I/O; ~3x faster than C++ equivalent
- `entropy_calc.asm` — Shannon entropy with SSE4.1 `pshufb` SIMD acceleration; 64-byte per-iteration processing; fixed-point log2 (avoids FPU dependency); threshold classification (>6.5 SUSPICIOUS, >7.5 ENCRYPTED)
- `linux_proc.asm` — `sys_getdents64` direct enumeration of `/proc` for kernel-path process listing on Linux

#### C++ Bridge (Tier 2)
- `asm_bridge.cpp` — CPU feature detection (SSE2/SSE4.1 via CPUID), SSN initialization, file memory-mapping helpers, MD5 hex formatting
- `process_diff.cpp` — O(n log n) dual-path PID delta engine; Windows: `NtQuerySystemInformation` (ASM) vs `CreateToolhelp32Snapshot`; Linux: `getdents64` (ASM) vs `/proc` C++ walk
- `vt_client.cpp` — VirusTotal API v3 HTTP client with token bucket rate limiting, exponential backoff (1s→30s), premium tier auto-detection, 24h TTL caching
- `file_scanner.cpp` — Cross-platform `std::filesystem` recursive walker with PE/ELF detection, per-file MD5+entropy dispatch, Windows digital signature verification via WinVerifyTrust
- `pe_parser.cpp` — Manual `IMAGE_NT_HEADERS` parser: import directory walk, section entropy, .NET CLR detection, debug directory, compile timestamp
- `elf_parser.cpp` — Manual ELF64/ELF32 parser: `PT_DYNAMIC` → `DT_NEEDED` library extraction, section entropy, ELF class detection
- `graph_builder.cpp` — Typed node/edge construction with threat scoring; Cytoscape.js JSON serialization
- `napi_bindings.cpp` — Node.js N-API bindings exposing all C++ functions to Electron main process

#### Electron Application (Tier 3)
- `main.js` — Scan pipeline orchestration, SQLite caching (better-sqlite3), keytar API key storage, PDF report generation (pdfmake + Puppeteer graph screenshot), IPC security validation
- `preload.js` — Type-validated contextBridge API; channel whitelist preventing XSS escalation

#### React UI (Tier 4)
- `GraphView.tsx` — Cytoscape.js with CoSE-Bilkent force layout; typed node/edge styles with threat-color coding; single-click inspector open; double-click OS file reveal; right-click context menu; edge hover tooltips; Cypher-style query filter; multi-select; PNG export
- `Dashboard.tsx` — D3.js entropy distribution histogram with threshold markers; VT detection bar chart; 6 stat cards; threat leaderboard with click-to-inspect
- `FileInspector.tsx` — Score bar, entropy gauge with threshold lines, MD5 copy, path copy, signature badge, VT live lookup, section list
- `ThreatPanel.tsx` — Real-time sorted critical/suspicious node list with threat tags
- `QueryBar.tsx` — Cypher-style filter input with 5 quick-query chips
- `SettingsPanel.tsx` — API key entry with OS keychain storage, platform info
- `ScanProgress.tsx` — Animated radar overlay with 4-phase scan pipeline progress

#### Build System
- `CMakeLists.txt` — Cross-platform NASM→.obj→shared library→N-API addon build
- `binding.gyp` — node-gyp configuration for Windows (MSVC) and Linux (GCC/Clang)
- `scripts/build-asm.js` — NASM build orchestrator + precomputed log2 LUT generator
- `vite.config.ts` — React/TypeScript bundler
- `.github/workflows/build.yml` — Windows-latest + ubuntu-22.04 matrix CI/CD with package and release jobs

#### Testing
- RFC 1321 MD5 test vectors (7 cases)
- Entropy threshold validation (7 cases including SSE4.1 boundary tests)
- Process diff integration tests (5 cases including multi-hidden and empty lists)
- Playwright E2E suite (25+ UI test cases)

---

## [Unreleased]

### Planned for v1.1
- eBPF-based secondary enumeration for Linux rootkit detection (cross-validates `getdents64` ASM path against kernel task_struct walk)
- Per-vendor VT result breakdown in FileInspector
- YARA rule scanning integration
- Timeline view for scan history delta comparison
- Auto-update via electron-updater
