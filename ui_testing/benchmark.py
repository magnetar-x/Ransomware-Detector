"""
ui_testing/benchmark.py – Overhead and benign workload runner for Member 3 validation.

Runs a benign file-creation/copy/read workload in a temporary directory and
records wall-clock duration plus basic process/system memory stats.

Usage:
    python3 ui_testing/benchmark.py
    python3 ui_testing/benchmark.py --files 50 --iterations 3
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time


def read_rss_kb() -> int | None:
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1])
    except OSError:
        pass
    return None


def run_benign_workload(work_dir: str, file_count: int, iterations: int) -> dict:
    os.makedirs(work_dir, exist_ok=True)
    src_dir = os.path.join(work_dir, "src")
    dst_dir = os.path.join(work_dir, "dst")
    os.makedirs(src_dir, exist_ok=True)
    os.makedirs(dst_dir, exist_ok=True)

    start = time.perf_counter()
    rss_start = read_rss_kb()

    for it in range(iterations):
        for i in range(file_count):
            src_file = os.path.join(src_dir, f"doc_{it}_{i}.txt")
            dst_file = os.path.join(dst_dir, f"doc_{it}_{i}.bak")
            content = f"Normal project note iteration={it} index={i}\n" * 25
            with open(src_file, "w", encoding="utf-8") as f:
                f.write(content)
            shutil.copyfile(src_file, dst_file)
            with open(dst_file, "r", encoding="utf-8") as f:
                _ = f.read()

    elapsed = time.perf_counter() - start
    rss_end = read_rss_kb()

    return {
        "iterations": iterations,
        "files_per_iter": file_count,
        "total_ops": iterations * file_count * 3,
        "elapsed_sec": round(elapsed, 4),
        "rss_start_kb": rss_start,
        "rss_end_kb": rss_end,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benign workload & overhead check")
    parser.add_argument("--files", type=int, default=30, help="Files per iteration")
    parser.add_argument("--iterations", type=int, default=2, help="Number of iterations")
    parser.add_argument("--keep", action="store_true", help="Keep temporary test folder")
    args = parser.parse_args()

    tmp_root = tempfile.mkdtemp(prefix="aegis_benign_")
    try:
        stats = run_benign_workload(tmp_root, file_count=args.files, iterations=args.iterations)
        print("[BENCHMARK] Benign workload complete:")
        for k, v in stats.items():
            print(f"  {k}: {v}")
    finally:
        if not args.keep and os.path.exists(tmp_root):
            shutil.rmtree(tmp_root, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
