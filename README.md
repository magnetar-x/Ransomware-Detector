<p align="center">
  <img src="https://img.shields.io/badge/eBPF-Kernel%20Instrumentation-critical?style=for-the-badge&logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/C-BPF%20Programs-orange?style=for-the-badge&logo=c&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

# Ransomware Detector

**A real-time Linux ransomware detection and mitigation system powered by eBPF kernel instrumentation and multi-layered user-space behavioral heuristics.**

Ransomware Detector intercepts filesystem syscalls at the kernel level — before any damage reaches disk — and feeds them through a high-speed heuristic scoring engine that identifies encryption behavior, kills malicious process trees, and broadcasts telemetry to a live SOC dashboard. Zero signatures. Zero filesystem scanning. Sub-50ms response time from first malicious write to process termination.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Linux Kernel Space                              │
│                                                                            │
│   sys_openat ──┐                                                           │
│   sys_write  ──┤── eBPF Tracepoint Probes ──► BPF Ring Buffer ──┐         │
│   sys_rename ──┤     (probes.bpf.c)              (fs_event_t)    │         │
│   sys_unlink ──┘                                                 │         │
└──────────────────────────────────────────────────────────────────┼─────────┘
                                                                   │
                              ┌────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           User Space — Detection Engine                    │
│                                                                            │
│   EventIngestor ──► ┌─────────────────────────────────┐                    │
│                     │  Multi-Layer Heuristic Pipeline  │                    │
│                     │                                  │                    │
│                     │  ① Shannon Entropy Analysis      │    ┌────────────┐ │
│                     │  ② Canary Honeyfile Tripwires    │───►│ Mitigator  │ │
│                     │  ③ Behavioral Sequence DAG       │    │ SIGSTOP →  │ │
│                     │  ④ I/O Velocity & Ext Mutation   │    │ SIGKILL    │ │
│                     └─────────────────────────────────┘    └────────────┘ │
│                               │                                            │
│                               ▼                                            │
│                     IPC Publisher (UDP + JSONL)                             │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Dashboard & Validation Suite                          │
│                                                                            │
│   Real-Time SOC Web Dashboard  ·  CLI Monitor  ·  Attack Simulators       │
│   Overhead Benchmarks  ·  False-Positive Validation                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Architecture

The system is divided into three independent, contract-bound modules built in parallel:

### Module 1 — Kernel eBPF Probes (`kernel/`)

Low-overhead eBPF tracepoint programs attached to `sys_openat`, `sys_write`, `sys_renameat2`, `sys_unlinkat`, and `sys_close`. Events are pushed through a BPF ring buffer as C structs and converted to Python dicts by a BCC-based loader class (`BPFEventStreamer`). In-kernel PID filtering and pseudo-filesystem exclusions ensure only relevant filesystem activity reaches user space.

**Tech:** C (eBPF restricted C), BCC, Linux tracepoints, BPF ring buffer

### Module 2 — Detection Engine (`engine/`)

The central brain of the detector. A high-speed Python daemon ingests kernel events and runs each through a four-layer heuristic scoring pipeline:

| Heuristic | Technique | Scoring |
|---|---|---|
| **Dual-Stage Shannon Entropy** | Inline 64-byte sample entropy + on-disk 4 KiB verification. Detects plaintext-to-ciphertext transitions and magic-byte overwrites. | +35 (magic overwrite), +30 (disk entropy) |
| **Canary Honeyfile Tripwires** | Hidden decoy files deployed at startup. Any process touching a canary is immediately flagged — zero tolerance. | +100 (instant kill) |
| **Behavioral Sequence DAG** | Per-PID finite state machine tracking destructive syscall sequences: in-place encryption (`OPEN→WRITE→RENAME`) and copy-and-shred (`OPEN(A)→WRITE(B)→UNLINK(A)`) loops. | Exponential: 10 × 1.5^C per cycle |
| **I/O Velocity & Extension Mutation** | Sliding-window rate tracking with exponential score decay. Detects rename bursts where many files receive the same new extension (e.g., `.locked`). | +50 (uniform extension burst) |

When a process's cumulative threat score crosses the configurable threshold (default 75.0), the mitigator executes a two-stage surgical response: instant `SIGSTOP` freeze of the entire process tree, followed by `SIGKILL` termination — with a `--dry-run` safe mode for testing.

**Tech:** Python 3.10+, ctypes, Shannon entropy, exponential decay scoring

### Module 3 — Testing, Benchmarks & Dashboard (`ui_testing/`)

Safe attack simulators (AES encryption loops, mass-rename storms, copy-and-shred), false-positive workload generators (compiler builds, archive compression, SQLite writes), overhead profilers, and a real-time web dashboard (FastAPI + WebSocket + Chart.js) consuming telemetry over UDP port 51423.

**Tech:** Python, FastAPI, Tailwind CSS, Chart.js, Rich/Textual TUI

---

## Data Contracts

Two shared contracts decouple the modules, enabling fully independent development:

### Contract A — Kernel → Engine (`common/event_defs.h`)

```c
struct fs_event_t {
    unsigned long long ts;          // Kernel monotonic timestamp (ns)
    unsigned int       pid;         // Process ID
    unsigned int       uid;         // User ID
    int                syscall_type;// SYS_OPEN=1, SYS_WRITE=2, SYS_RENAME=3, SYS_UNLINK=4
    unsigned long      bytes_req;   // Bytes written
    char comm[16];                  // Process command name
    char filename[256];             // Target file path
};
```

### Contract B — Engine → Dashboard (`common/ipc_schema.json`)

```json
{
  "timestamp": 1762473600.123,
  "pid": 48291,
  "process_name": "evil_crypt",
  "threat_score": 95.5,
  "action_taken": "SIGKILL",
  "trigger_reasons": [
    "HIGH_INLINE_ENTROPY (7.89 bits/byte)",
    "DESTRUCTIVE_SEQUENCE_DAG (OPEN→WRITE→RENAME)"
  ]
}
```

Transport: Non-blocking UDP datagrams to `127.0.0.1:51423` + append-only JSONL log at `/tmp/aegis_telemetry.jsonl`.

---

## Repository Structure

```text
Ransomware-Detector/
├── common/                          # Shared data contracts (read-only after initial setup)
│   ├── event_defs.h                 # [Contract A] C struct: Kernel ↔ Engine
│   └── ipc_schema.json             # [Contract B] JSON schema: Engine ↔ Dashboard
│
├── kernel/                          # Module 1: eBPF kernel probes & BCC loader
│   └── (under development)
│
├── engine/                          # Module 2: User-space detection engine
│   ├── main_daemon.py              # CLI orchestrator (--mock / --live / --dry-run)
│   ├── ingestor.py                 # Dual-mode event consumer (live BCC ↔ mock streamer)
│   ├── mock_streamer.py            # Synthetic kernel event generator (6 scenarios)
│   ├── state_tracker.py            # Per-PID sliding window, score decay, velocity tracking
│   ├── mitigator.py                # SIGSTOP → SIGKILL cascade with --dry-run safe mode
│   ├── ipc_publisher.py            # Non-blocking UDP + JSONL telemetry broadcaster
│   ├── config.py                   # Central constants and tunable thresholds
│   ├── heuristics/
│   │   ├── entropy.py              # Dual-stage Shannon entropy analyzer
│   │   ├── canary.py               # Honeyfile deployment & zero-tolerance tripwires
│   │   └── sequence_dag.py         # Behavioral syscall sequence state machine
│   └── tests/                      # 100 unit + integration tests (pytest)
│       ├── test_integration.py     # End-to-end detection benchmarks
│       ├── test_entropy.py         # Shannon entropy correctness & staging
│       ├── test_canary.py          # Honeyfile deployment & tripwire verification
│       ├── test_sequence_dag.py    # DAG pattern matching & exponential scoring
│       ├── test_state_tracker.py   # Score decay, velocity, extension uniformity
│       ├── test_mitigator.py       # Safe mode, whitelist, signal dispatch
│       ├── test_ipc_publisher.py   # Schema compliance, UDP broadcast, JSONL logging
│       ├── test_mock_streamer.py   # Event shape, scenario content, lifecycle
│       └── test_ingestor.py        # ctypes struct layout, dual-mode ingestion
│
└── ui_testing/                      # Module 3: Simulators, benchmarks & dashboard
    └── (under development)
```

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Kernel Instrumentation | C (eBPF), BCC, Linux Tracepoints | Zero-overhead syscall interception via BPF ring buffer |
| Detection Engine | Python 3.10+, ctypes | Behavioral heuristics, Shannon entropy, process mitigation |
| Inter-Module IPC | UDP datagrams, JSONL | Fire-and-forget non-blocking telemetry transport |
| Dashboard | FastAPI, WebSocket, Chart.js, Tailwind CSS | Real-time SOC visualization |
| Testing | pytest, Mock Streamer | 100 automated tests with dry-run safe mode |

---

## Current Status: Under Active Development

> **This project is being built and integrated by a three-person team. Individual modules are being developed on separate feature branches and merged upon completion.**

| Module | Branch | Status | Tests |
|---|---|---|---|
| **Kernel eBPF Probes** (`kernel/`) | `feat/kernel-probes` | 🔨 In Progress | — |
| **Detection Engine** (`engine/`) | `feat/core-engine` | ✅ Complete | 100/100 passing |
| **Testing & Dashboard** (`ui_testing/`) | `feat/testing-ui` | 🔨 In Progress | — |

### Engine Test Results

```
============================= 100 passed in 9.87s =============================
```

Key validations:
- ✅ **Zero false positives** on benign compiler and archive workloads at 15,000 events/sec
- ✅ **Sub-50ms detection latency** from first malicious event to process termination
- ✅ **Canary instant-kill** — honeyfile tampering triggers threat score ≥ 100 immediately
- ✅ **Selective mitigation** — mixed workloads terminate only the ransomware PID
- ✅ **Full IPC schema compliance** — every telemetry packet validates against `common/ipc_schema.json`

---

## Requirements

- Linux kernel ≥ 5.8 (for BPF ring buffer support)
- Python ≥ 3.10
- BCC (BPF Compiler Collection) — for live kernel probe mode
- Root privileges — required only for loading eBPF programs (`--live` mode)

> **Note:** The engine can run entirely without root or BCC using `--mock` mode, which uses a built-in synthetic event generator for development and testing.

---

## License

MIT
