# 👻 PhantomScope
### Rootkit Detection & Forensic Analysis Platform

[![Purpose](https://img.shields.io/badge/Purpose-Security%20Research-red?style=for-the-badge)](https://github.com/Unreal7123/phantoom-roootkit)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20%7C%20Linux-blue?style=for-the-badge)](https://github.com/Unreal7123/phantoom-roootkit)
[![Architecture](https://img.shields.io/badge/Arch-x86--64-orange?style=for-the-badge)](https://github.com/Unreal7123/phantoom-roootkit)
[![Stack](https://img.shields.io/badge/Stack-NASM%20%7C%20C%2B%2B17%20%7C%20Electron%20%7C%20React-purple?style=for-the-badge)](https://github.com/Unreal7123/phantoom-roootkit)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

> ⚠️ **Authorized use only.** PhantomScope is designed exclusively for security researchers, incident responders, and malware analysts operating on systems they own or have **explicit written authorization** to analyze. Unauthorized use may violate applicable laws.

---

## 📖 About

**PhantomScope** is a low-level rootkit detection and forensic analysis platform that leverages **direct x86-64 syscalls**, **Shannon entropy analysis**, and **VirusTotal API integration** to detect hidden processes, packed malware, and suspicious binaries — even when rootkits have hooked user-mode APIs.

Built with a **4-tier architecture** spanning raw NASM assembly to a React-based UI, PhantomScope is designed for hands-on security research, malware triage, and incident response.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  T4   React 18 + TypeScript  │  Cytoscape.js  │  D3.js v7  │
├─────────────────────────────────────────────────────────────┤
│  T3   Electron.js (Node 20+) │  IPC Bridge    │  SQLite     │
├─────────────────────────────────────────────────────────────┤
│  T2   C++17 Bridge           │  VT Client     │  Scanner    │
├─────────────────────────────────────────────────────────────┤
│  T1   NASM x86-64            │  Direct Syscall│  SSE4.1     │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔍 Core Detection Methods

PhantomScope detects hidden processes by comparing **two independent enumeration paths**:

| Path | Method | Hookable by Rootkit? |
|------|--------|----------------------|
| **Kernel** | `NtQuerySystemInformation` via direct `syscall` (bypasses ntdll.dll) | ❌ No |
| **Usermode** | `CreateToolhelp32Snapshot` / `/proc` walk | ✅ Yes |

> **Any PID present in the kernel list but absent from the usermode list = HIDDEN PROCESS (Rootkit Indicator)**

### Why Direct Syscalls?

Modern rootkits hook user-mode API entry points in `ntdll.dll`. Standard tools are blind to this:

```
Application → kernel32.dll → ntdll.NtOpenProcess [HOOKED by rootkit] → kernel
```

PhantomScope bypasses the hook entirely using **Hell's Gate** SSN resolution:

```nasm
; syscall_wrapper.asm — Dynamic SSN resolution
; Walks ntdll export table at runtime, reads SSN from function prologue
mov r10, rcx       ; NT ABI requirement
mov eax, <SSN>     ; Resolved at runtime — not hardcoded
syscall            ; Direct kernel transition — zero ntdll involvement
```

---

## ✨ Features

### 🔎 Hidden Process Detection
- **Windows**: `NtQuerySystemInformation(SystemProcessInformation=5)` via direct ASM syscall with dynamic SSN resolution
- **Linux**: `sys_getdents64` on `/proc` from NASM vs usermode `/proc` walk comparison
- PID set delta reveals rootkit-hidden processes instantly

### 📊 Shannon Entropy Analysis
- **SSE4.1 SIMD-accelerated** byte frequency histogram (`pshufb` for 16-way parallel counting)
- Per-section entropy analysis for PE and ELF binaries
- Thresholds:
  - `H > 6.5` → **SUSPICIOUS** (likely packed)
  - `H > 7.5` → **ENCRYPTED** (likely obfuscated/ransomware)

### #️⃣ MD5 Engine
- Pure **NASM x86-64 RFC 1321** implementation
- Memory-mapped file I/O (zero-copy via `MapViewOfFile` / `mmap`)
- **SSE2-optimized** round functions — ~3x faster than equivalent C++

### 🌐 VirusTotal Integration
- API v3: `GET /api/v3/files/{md5}`
- Token bucket rate limiting (4 req/min free / 500 req/min premium)
- Exponential backoff on `429` responses: `1s → 2s → 4s → 8s → 16s`
- **24-hour SQLite result cache** to minimize API usage
- API key stored in OS credential manager (DPAPI / libsecret / Keychain) — **never in config files**

### 🕸️ Graph Visualization (Cytoscape.js)
BloodHound-inspired directed graph with node and edge classification:

| Node Type | Description |
|-----------|-------------|
| `PHProcess` | Visible process (both enumeration paths) |
| `PHHiddenProcess` | 🔴 **ROOTKIT INDICATOR** — kernel only |
| `PHFile` | Executable / DLL on disk |
| `PHService` | Windows service / systemd unit |
| `PHDriver` | Kernel driver (`.sys` / `.ko`) |

| Edge Type | Description |
|-----------|-------------|
| `PHSpawnsProcess` | Parent → child process relationship |
| `PHLoadsModule` | Process → loaded DLL |
| `PHImports` | Static PE/ELF import |
| `PHHijackPath` | Unquoted service path hijack vector |
| `PHInjects` | Code injection relationship |

### 🎯 Threat Scoring Engine

```
score = 0
  + 60  if process is hidden (kernel/usermode delta)
  + 30  if entropy > 7.5 (encrypted payload)
  + 20  if entropy > 6.5 (packed binary)
  + 40  if VirusTotal detections > 0
  + 10  if unsigned binary
  + 15  if executable in user-writable directory
  ─────────────────────────────────────────────
  ≥ 70  →  CRITICAL      🔴
  ≥ 40  →  SUSPICIOUS    🟠
  ≥ 10  →  INFORMATIONAL 🔵
     0  →  CLEAN         🟢
```

---

## 📁 Project Structure

```
phantoom-roootkit/
├── asm/
│   ├── process_enum.asm      # Windows NtQuerySystemInformation direct syscall
│   ├── syscall_wrapper.asm   # Dynamic SSN resolution (Hell's Gate)
│   ├── md5_engine.asm        # RFC 1321 MD5 with SSE2 optimization
│   ├── entropy_calc.asm      # Shannon entropy with SSE4.1 SIMD
│   └── linux_proc.asm        # Linux sys_getdents64 enumeration
├── src/
│   ├── bridge/
│   │   ├── asm_bridge.h/cpp  # C++ ↔ NASM FFI interface
│   │   ├── process_diff.cpp  # Hidden process detection engine
│   │   ├── vt_client.cpp     # VirusTotal API v3 client
│   │   ├── file_scanner.cpp  # Filesystem walker + PE/ELF parser
│   │   ├── graph_builder.cpp # Cytoscape.js JSON constructor
│   │   └── napi_bindings.cpp # Node.js N-API glue layer
│   ├── app/
│   │   ├── main.js           # Electron main process
│   │   └── preload.js        # Secure IPC bridge
│   └── ui/
│       ├── App.tsx
│       ├── store/scanStore.ts # Zustand global state
│       └── components/
│           ├── GraphView.tsx  # Cytoscape.js graph
│           ├── Dashboard.tsx  # D3 analytics dashboard
│           ├── FileInspector.tsx
│           ├── ThreatPanel.tsx
│           ├── QueryBar.tsx   # Cypher-style filter
│           └── SettingsPanel.tsx
├── tests/
│   ├── unit/test_md5.cpp      # RFC 1321 test vectors
│   └── unit/test_entropy.cpp  # Entropy threshold validation
├── scripts/
│   └── build-asm.js           # NASM build orchestrator
├── .github/workflows/         # CI/CD pipelines
├── CMakeLists.txt
├── binding.gyp
├── playwright.config.ts
├── vite.config.ts
├── tsconfig.json
├── CHANGELOG.md
└── package.json
```

---

## ⚙️ Prerequisites

### Windows
- Windows 10/11 x64
- Visual Studio 2022 Build Tools (C++, Windows SDK 10.0.22621)
- NASM 2.16+ (add to PATH)
- Node.js 20 LTS
- Python 3.x (for node-gyp)
- `SeDebugPrivilege` (auto-requested on launch)

### Linux
- Ubuntu 20.04+ x64 (or equivalent)
- GCC 11+ or Clang 14+
- NASM 2.16+: `sudo apt install nasm`
- Node.js 20 LTS
- `libcurl4-dev`, `libsecret-1-dev`, CMake 3.20+
- `CAP_SYS_PTRACE` or root for cross-UID `/proc` access

---

## 🚀 Build & Run

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

### Development Mode

```bash
# Start dev server with hot reload
npm start

# Run unit tests (MD5 vectors, entropy validation)
npm test

# Run E2E tests (requires display)
npm run test:e2e
```

---

## 🔐 Security Architecture

| Concern | Mitigation |
|---------|------------|
| API key exposure | OS credential manager (DPAPI / libsecret / Keychain) via `keytar` |
| Renderer XSS escalation | `contextIsolation: true`, `nodeIntegration: false`, preload whitelist |
| IPC injection | JSON schema validation on all IPC messages in main process |
| Privilege escalation | Only requests `SeDebugPrivilege` — no UAC bypass attempted |
| Outbound connections | Exclusively to `virustotal.com` API endpoint |

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|------------|
| **Assembly** | NASM x86-64 (SSE2 / SSE4.1) |
| **Native** | C++17 + Node.js N-API (`binding.gyp`) |
| **Build** | CMake 3.20 |
| **Desktop** | Electron.js (Node 20+) |
| **Frontend** | React 18 + TypeScript + Vite |
| **Visualization** | Cytoscape.js + D3.js v7 |
| **State** | Zustand |
| **Testing** | Playwright (E2E) + custom C++ unit tests |
| **CI/CD** | GitHub Actions |

---

## ⚖️ Legal & Ethical Use

This tool is intended **strictly** for:
- Authorized penetration testing and red team operations
- Malware analysis in isolated lab environments
- Incident response on systems you own or have written authorization to analyze
- Academic and security research

**Do NOT use this tool on systems you do not own or do not have explicit authorization to test.** Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), and other applicable laws.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 Rohit Chauhan

---

<p align="center">
  <img src="https://img.shields.io/badge/Hunt%20Rootkits-Not%20People-red?style=flat-square" />
  <img src="https://img.shields.io/badge/Direct%20Syscalls-Hell's%20Gate-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/Built%20By-Rohit%20Chauhan-blueviolet?style=flat-square" />
</p>

<p align="center">Built with 🔬 for the security research community</p>
