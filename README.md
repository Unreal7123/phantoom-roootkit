# PhantomScope
### Rootkit Detection & Forensic Analysis Platform

[![Security Research](https://img.shields.io/badge/purpose-security%20research-red)]()
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Linux-blue)]()
[![Architecture](https://img.shields.io/badge/arch-x86--64-orange)]()
[![Stack](https://img.shields.io/badge/stack-NASM%20%7C%20C%2B%2B17%20%7C%20Electron%20%7C%20React-purple)]()

> **Authorized use only.** PhantomScope is designed exclusively for security researchers, incident responders, and malware analysts operating on systems they own or have explicit written authorization to analyze.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  T4  React 18 + TypeScript  │  Cytoscape.js  │  D3.js v7        │
├─────────────────────────────────────────────────────────────────┤
│  T3  Electron.js (Node 20+) │  IPC Bridge    │  SQLite Cache    │
├─────────────────────────────────────────────────────────────────┤
│  T2  C++17 Bridge           │  VT Client     │  File Scanner    │
├─────────────────────────────────────────────────────────────────┤
│  T1  NASM x86-64            │  Direct Syscall│  SSE4.1 Entropy  │
└─────────────────────────────────────────────────────────────────┘
```

## Core Detection Method

PhantomScope detects hidden processes by comparing **two independent enumeration paths**:

| Path | Method | Can be hooked by rootkit? |
|------|--------|--------------------------|
| **Kernel** | `NtQuerySystemInformation` via direct `syscall` instruction | ❌ No (bypasses ntdll.dll entirely) |
| **Usermode** | `CreateToolhelp32Snapshot` / `/proc` walk | ✅ Yes |

**Any PID present in the kernel list but absent from the usermode list is definitively HIDDEN.**

### Why Direct Syscalls?

Modern rootkits operate at ring-0 and hook user-mode API entry points in `ntdll.dll`. When a tool calls `OpenProcess()`, the call flows through:

```
Application → kernel32.dll → ntdll.NtOpenProcess [HOOKED] → kernel
                                       ↑
                              rootkit patches here
```

PhantomScope bypasses this entirely:

```nasm
; syscall_wrapper.asm — Hell's Gate SSN resolution
; Walks ntdll export table at runtime to read SSN from function prologue
; Then executes:
mov r10, rcx          ; NT ABI requirement
mov eax, <resolved_SSN>
syscall               ; Direct kernel transition — no ntdll hooks
```

## Features

### Process Enumeration
- **Windows**: `NtQuerySystemInformation(SystemProcessInformation=5)` via direct ASM syscall with dynamic SSN resolution ("Hell's Gate" technique)
- **Linux**: `sys_getdents64` on `/proc` from NASM with usermode `/proc` walk comparison
- Hidden process detection via PID set delta

### Shannon Entropy Analysis
- SSE4.1 SIMD-accelerated byte frequency histogram (`pshufb` for 16-way parallel counting)
- Processes 64-byte chunks per iteration
- Fixed-point log2 approximation (avoids FPU dependency)
- Per-section entropy for PE/ELF binaries
- **Threshold: H > 6.5 = SUSPICIOUS, H > 7.5 = ENCRYPTED**

### MD5 Engine
- Pure NASM x86-64 RFC 1321 implementation
- Memory-mapped file I/O (zero-copy: `MapViewOfFile` / `mmap`)
- SSE2-optimized round functions F/G/H/I
- ~3x faster than equivalent C++ implementation

### VirusTotal Integration
- API v3 endpoint: `GET /api/v3/files/{md5}`
- Token bucket rate limiting (4 req/min free, 500 req/min premium)
- Exponential backoff: 1s → 2s → 4s → 8s → 16s on 429
- 24-hour SQLite result cache
- API key stored in OS credential manager (never in config files)

### Graph Visualization (Cytoscape.js)
BloodHound-inspired directed graph with:

| Node Type | Description |
|-----------|-------------|
| `PHProcess` | Visible process (both paths) |
| `PHHiddenProcess` | **ROOTKIT INDICATOR** — kernel only |
| `PHFile` | Executable/DLL on disk |
| `PHService` | Windows service / systemd unit |
| `PHDriver` | Kernel driver (.sys / .ko) |

| Edge Type | Description |
|-----------|-------------|
| `PHSpawnsProcess` | Parent → child process |
| `PHLoadsModule` | Process → loaded DLL |
| `PHImports` | Static PE/ELF import |
| `PHHijackPath` | Unquoted service path hijack vector |
| `PHInjects` | Code injection relationship |

### Threat Scoring

```
score = 0
+ 60  if process hidden (kernel/usermode delta)
+ 30  if entropy > 7.5 (encrypted)
+ 20  if entropy > 6.5 (packed)
+ 40  if VT detections > 0
+ 10  if unsigned binary
+ 15  if executable in user-writable directory
────────────────────────────────
≥ 70  → CRITICAL  (RED node)
≥ 40  → SUSPICIOUS (AMBER node)
≥ 10  → INFORMATIONAL (BLUE node)
  0   → CLEAN (GREEN node)
```

## Prerequisites

### Windows
```
- Windows 10/11 x64
- Visual Studio 2022 Build Tools (C++, Windows SDK 10.0.22621)
- NASM 2.16+ (add to PATH)
- Node.js 20 LTS
- Python 3.x (for node-gyp)
- SeDebugPrivilege (auto-requested on launch)
```

### Linux
```
- Ubuntu 20.04+ x64 (or equivalent)
- GCC 11+ or Clang 14+
- NASM 2.16+ (sudo apt install nasm)
- Node.js 20 LTS
- libcurl4-dev, libsecret-1-dev
- CMake 3.20+
- CAP_SYS_PTRACE or root for cross-UID /proc access
```

## Build

```bash
# Install dependencies
npm install

# Build NASM assembly (generates .obj files)
npm run build:asm

# Build C++ N-API native addon
npm run build:native

# Build React UI
npm run build:react

# Package for distribution
npm run package:win    # Windows NSIS installer
npm run package:linux  # Linux AppImage + .deb + .rpm
```

## Development

```bash
# Start dev server (hot reload)
npm start

# Run unit tests (MD5 test vectors, entropy validation)
npm test

# Run E2E tests (requires display)
npm run test:e2e
```

## File Structure

```
phantomscope/
├── asm/
│   ├── process_enum.asm      Windows NtQuerySystemInformation direct syscall
│   ├── syscall_wrapper.asm   Dynamic SSN resolution (Hell's Gate)
│   ├── md5_engine.asm        RFC 1321 MD5 with SSE2
│   ├── entropy_calc.asm      Shannon entropy with SSE4.1
│   └── linux_proc.asm        Linux sys_getdents64 enumeration
├── src/
│   ├── bridge/
│   │   ├── asm_bridge.h/cpp  C++ ↔ NASM FFI interface
│   │   ├── process_diff.cpp  Hidden process detection engine
│   │   ├── vt_client.cpp     VirusTotal API v3 client
│   │   ├── file_scanner.cpp  Filesystem walker + PE/ELF parser
│   │   ├── graph_builder.cpp Cytoscape.js JSON constructor
│   │   └── napi_bindings.cpp Node.js N-API glue layer
│   ├── app/
│   │   ├── main.js           Electron main process
│   │   └── preload.js        Secure IPC bridge
│   └── ui/
│       ├── App.tsx
│       ├── store/scanStore.ts  Zustand global state
│       ├── components/
│       │   ├── GraphView.tsx   Cytoscape.js graph
│       │   ├── Dashboard.tsx   D3 analytics dashboard
│       │   ├── FileInspector.tsx
│       │   ├── ThreatPanel.tsx
│       │   ├── QueryBar.tsx    Cypher-style filter
│       │   └── SettingsPanel.tsx
│       └── styles/app.css
├── tests/
│   ├── unit/test_md5.cpp     RFC 1321 test vectors
│   └── unit/test_entropy.cpp Entropy threshold validation
├── scripts/
│   └── build-asm.js          NASM build orchestrator
├── CMakeLists.txt
├── binding.gyp
└── package.json
```

## Security Architecture

| Concern | Mitigation |
|---------|-----------|
| API key exposure | OS credential manager (DPAPI/libsecret/Keychain) via keytar |
| Renderer XSS escalation | `contextIsolation: true`, `nodeIntegration: false`, preload whitelist |
| IPC injection | JSON schema validation on all IPC messages in main process |
| Privilege escalation | Only requests `SeDebugPrivilege` (no UAC bypass attempted) |
| Outbound connections | Only to `virustotal.com` API endpoint |

## License

Security Research Tool — Authorized Use Only

This software is provided for legitimate security research, incident response, and malware analysis purposes only. Users must comply with all applicable laws and obtain proper authorization before scanning any system.
#   p h a n t o o m - r o o o t k i t  
 