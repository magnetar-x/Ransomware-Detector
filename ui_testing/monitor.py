"""
ui_testing/monitor.py – Live CLI telemetry monitor for Aegis Ransomware Detector.

Listens on UDP 127.0.0.1:51423 and/or tails /tmp/aegis_telemetry.jsonl.
Usage:
    python3 ui_testing/monitor.py
    python3 ui_testing/monitor.py --jsonl-only
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime

DEFAULT_UDP_HOST = "127.0.0.1"
DEFAULT_UDP_PORT = 51423
DEFAULT_JSONL_PATH = "/tmp/aegis_telemetry.jsonl"


def format_ts(timestamp_ms: int) -> str:
    dt = datetime.fromtimestamp(timestamp_ms / 1000.0)
    return dt.strftime("%H:%M:%S.%f")[:-3]


def render_packet(pkt: dict, show_metrics: bool = False) -> None:
    pkt_type = pkt.get("packet_type", "UNKNOWN")
    ts = format_ts(int(pkt.get("timestamp_ms", time.time() * 1000)))
    pid = pkt.get("pid", -1)
    comm = pkt.get("comm", "?")
    uid = pkt.get("uid", -1)
    score = pkt.get("risk_score", 0.0)
    threshold = pkt.get("threshold", 75.0)
    action = pkt.get("action_taken", "NONE")
    reasons = pkt.get("triggered_heuristics", [])

    if pkt_type == "ALERT":
        reason_str = ", ".join(reasons) if reasons else "NONE"
        print(
            f"[{ts}] [ALERT] pid={pid} comm={comm} uid={uid} "
            f"score={score:.1f}/{threshold:.1f} action={action} reasons=[{reason_str}]",
            flush=True,
        )
    elif pkt_type == "METRIC" and show_metrics:
        metrics = pkt.get("system_metrics", {})
        print(
            f"[{ts}] [METRIC] pid={pid} comm={comm} score={score:.1f} "
            f"action={action} metrics={json.dumps(metrics)}",
            flush=True,
        )


def run_udp_listener(host: str, port: int, show_metrics: bool) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)
    print(f"Listening for UDP telemetry on {host}:{port}... (Ctrl+C to stop)", flush=True)

    try:
        while True:
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            for line in data.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    pkt = json.loads(line)
                    render_packet(pkt, show_metrics=show_metrics)
                except json.JSONDecodeError:
                    print(f"[RAW] {line}", flush=True)
    except KeyboardInterrupt:
        print("\nStopped monitor.", flush=True)
    finally:
        sock.close()


def run_jsonl_tail(path: str, show_metrics: bool) -> None:
    print(f"Tailing JSONL telemetry from {path}... (Ctrl+C to stop)", flush=True)
    while not os.path.exists(path):
        time.sleep(0.2)

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    pkt = json.loads(line)
                    render_packet(pkt, show_metrics=show_metrics)
                except json.JSONDecodeError:
                    print(f"[RAW] {line}", flush=True)
    except KeyboardInterrupt:
        print("\nStopped tailing.", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Live telemetry monitor for Ransomware Detector")
    parser.add_argument("--host", default=DEFAULT_UDP_HOST, help="UDP listen host")
    parser.add_argument("--port", type=int, default=DEFAULT_UDP_PORT, help="UDP listen port")
    parser.add_argument("--jsonl-path", default=DEFAULT_JSONL_PATH, help="Path to telemetry JSONL file")
    parser.add_argument("--jsonl-only", action="store_true", help="Tail JSONL file instead of binding UDP")
    parser.add_argument("--metrics", action="store_true", help="Also print METRIC packets")
    args = parser.parse_args()

    if args.jsonl_only:
        run_jsonl_tail(args.jsonl_path, show_metrics=args.metrics)
    else:
        run_udp_listener(args.host, args.port, show_metrics=args.metrics)
    return 0


if __name__ == "__main__":
    sys.exit(main())
