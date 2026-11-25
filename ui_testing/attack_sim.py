"""
ui_testing/attack_sim.py – Safe synthetic ransomware behavior simulator.

Operates strictly inside an isolated sandbox folder (default: /tmp/ransom_sandbox)
or the configured canary directory (/tmp/aegis_canary_zone) for canary tests.

Usage:
    python3 ui_testing/attack_sim.py --scenario all
    python3 ui_testing/attack_sim.py --scenario entropy --files 15
    python3 ui_testing/attack_sim.py --scenario rename --ext .locked
    python3 ui_testing/attack_sim.py --scenario dag
    python3 ui_testing/attack_sim.py --scenario canary --cleanup
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time

DEFAULT_SANDBOX_DIR = "/tmp/ransom_sandbox"
DEFAULT_CANARY_DIR = "/tmp/aegis_canary_zone"


def prepare_sandbox(sandbox_dir: str, file_count: int) -> list[str]:
    os.makedirs(sandbox_dir, exist_ok=True)
    paths: list[str] = []
    for i in range(file_count):
        p = os.path.join(sandbox_dir, f"sample_doc_{i:02d}.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"Benign test document #{i}\n" * 40)
        paths.append(p)
    return paths


def simulate_high_entropy(paths: list[str], delay_ms: float = 10.0) -> None:
    print(f"[SIM:entropy] Overwriting {len(paths)} files with high-entropy bytes...")
    for p in paths:
        with open(p, "r+b") as f:
            f.seek(0)
            f.write(os.urandom(4096))
            f.flush()
            os.fsync(f.fileno())
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)


def simulate_mass_rename(paths: list[str], ext: str = ".locked", delay_ms: float = 10.0) -> list[str]:
    if not ext.startswith("."):
        ext = "." + ext
    print(f"[SIM:rename] Renaming {len(paths)} files to '{ext}'...")
    renamed: list[str] = []
    for p in paths:
        target = p + ext
        os.replace(p, target)
        renamed.append(target)
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
    return renamed


def simulate_sequence_dag(sandbox_dir: str, cycles: int = 8) -> None:
    print(f"[SIM:dag] Running {cycles} destructive open/write/rename & copy-unlink cycles...")
    for i in range(cycles):
        src = os.path.join(sandbox_dir, f"dag_src_{i}.txt")
        tmp_enc = os.path.join(sandbox_dir, f"dag_tmp_{i}.bin")
        final_enc = os.path.join(sandbox_dir, f"dag_enc_{i}.locked")

        # Pattern 1: OPEN -> WRITE -> RENAME
        with open(src, "w", encoding="utf-8") as f:
            f.write(f"Plaintext payload {i}\n" * 20)
        with open(src, "r+b") as f:
            f.write(os.urandom(2048))
            f.flush()
        os.replace(src, final_enc)

        # Pattern 2: OPEN(A) -> WRITE(B) -> UNLINK(A)
        orig = os.path.join(sandbox_dir, f"shred_orig_{i}.txt")
        with open(orig, "w", encoding="utf-8") as f:
            f.write(f"Original file {i}\n" * 20)
        with open(orig, "rb") as fin, open(tmp_enc, "wb") as fout:
            _ = fin.read()
            fout.write(os.urandom(2048))
            fout.flush()
        os.unlink(orig)
        if os.path.exists(tmp_enc):
            os.unlink(tmp_enc)


def simulate_canary_touch(canary_dir: str) -> None:
    os.makedirs(canary_dir, exist_ok=True)
    existing = []
    for root, _, files in os.walk(canary_dir):
        for name in files:
            existing.append(os.path.join(root, name))

    target = existing[0] if existing else os.path.join(canary_dir, ".canary_probe_test")
    print(f"[SIM:canary] Touching canary target: {target}")
    with open(target, "ab") as f:
        f.write(os.urandom(64))
        f.flush()


def cleanup_dir(target_dir: str, allow_canary: bool = False) -> None:
    resolved = os.path.realpath(target_dir)
    canary_resolved = os.path.realpath(DEFAULT_CANARY_DIR)
    if resolved == "/" or resolved == os.path.realpath(tempfile.gettempdir()):
        print(f"[CLEANUP] Refusing to delete unsafe path: {resolved}")
        return
    if resolved == canary_resolved and not allow_canary:
        print(f"[CLEANUP] Skipping canary dir {resolved} (use --allow-canary-cleanup to remove).")
        return
    if os.path.exists(resolved):
        shutil.rmtree(resolved)
        print(f"[CLEANUP] Removed {resolved}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe synthetic ransomware simulator")
    parser.add_argument(
        "--scenario",
        choices=["entropy", "rename", "dag", "canary", "all"],
        default="all",
        help="Attack behavior scenario to simulate",
    )
    parser.add_argument("--sandbox-dir", default=DEFAULT_SANDBOX_DIR, help="Isolated test directory")
    parser.add_argument("--canary-dir", default=DEFAULT_CANARY_DIR, help="Canary directory for canary test")
    parser.add_argument("--files", type=int, default=12, help="Number of sandbox files to generate")
    parser.add_argument("--ext", default=".locked", help="Extension used during rename simulation")
    parser.add_argument("--cycles", type=int, default=8, help="Number of DAG cycles to run")
    parser.add_argument("--delay-ms", type=float, default=10.0, help="Delay between file operations in ms")
    parser.add_argument("--cleanup", action="store_true", help="Remove sandbox directory after running")
    parser.add_argument("--allow-canary-cleanup", action="store_true", help="Also allow cleaning canary dir")
    args = parser.parse_args()

    if args.scenario in ("entropy", "rename", "all"):
        paths = prepare_sandbox(args.sandbox_dir, args.files)
        if args.scenario == "entropy":
            simulate_high_entropy(paths, delay_ms=args.delay_ms)
        elif args.scenario == "rename":
            simulate_high_entropy(paths, delay_ms=args.delay_ms)
            simulate_mass_rename(paths, ext=args.ext, delay_ms=args.delay_ms)
        else:
            simulate_high_entropy(paths, delay_ms=args.delay_ms)
            renamed = simulate_mass_rename(paths, ext=args.ext, delay_ms=args.delay_ms)
            simulate_sequence_dag(args.sandbox_dir, cycles=args.cycles)
            for rp in renamed:
                if os.path.exists(rp):
                    os.unlink(rp)

    if args.scenario == "dag":
        os.makedirs(args.sandbox_dir, exist_ok=True)
        simulate_sequence_dag(args.sandbox_dir, cycles=args.cycles)

    if args.scenario in ("canary", "all"):
        simulate_canary_touch(args.canary_dir)

    if args.cleanup:
        cleanup_dir(args.sandbox_dir, allow_canary=args.allow_canary_cleanup)

    print("[SIM] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
