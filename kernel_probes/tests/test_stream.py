#!/usr/bin/env python3
"""Print live AegisBPF events; requires root, BCC, and kernel headers."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from kernel_probes.probe_loader import BPFEventStreamer  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Print AegisBPF filesystem events")
    parser.add_argument("--ignore-pid", action="append", type=int, default=[])
    args = parser.parse_args()
    streamer = BPFEventStreamer(ignore_pids=args.ignore_pid)

    def print_event(event: dict) -> None:
        payload = event["payload_sample"]
        print(
            f"{event['timestamp_ns']} pid={event['pid']} tid={event['tid']} "
            f"type={event['event_type']} fd={event['fd']} bytes={event['bytes_count']} "
            f"comm={event['comm']!r} file={event['filename']!r} "
            f"new={event['new_filename']!r} payload={len(payload)}B",
            flush=True,
        )

    try:
        streamer.register_callback(print_event)
        streamer.start_blocking_loop()
    except PermissionError as exc:
        print(f"permission denied: run as root ({exc})", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        streamer.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
