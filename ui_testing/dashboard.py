"""
ui_testing/dashboard.py – Zero-dependency Web Dashboard for Aegis Ransomware Detector.

Listens on UDP 127.0.0.1:51423 and tails /tmp/aegis_telemetry.jsonl while serving
a live web UI on http://127.0.0.1:8080 with interactive attack_sim & benchmark controls.

Usage:
    python3 ui_testing/dashboard.py
    python3 ui_testing/dashboard.py --port 8080 --jsonl-path /tmp/aegis_telemetry.jsonl
"""

from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse

DEFAULT_WEB_HOST = "0.0.0.0"
DEFAULT_WEB_PORT = 8080
DEFAULT_UDP_HOST = "127.0.0.1"
DEFAULT_UDP_PORT = 51423
DEFAULT_JSONL_PATH = "/tmp/aegis_telemetry.jsonl"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ATTACK_SIM_PATH = os.path.join(SCRIPT_DIR, "attack_sim.py")
BENCHMARK_PATH = os.path.join(SCRIPT_DIR, "benchmark.py")

MAX_EVENTS = 250


class TelemetryStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.events: deque[dict] = deque(maxlen=MAX_EVENTS)
        self.alert_count = 0
        self.metric_count = 0
        self.blocked_pids: set[int] = set()
        self.latest_metrics: dict = {}
        self.last_benchmark: dict | None = None
        self.last_sim_output: str = ""
        self._seen_keys: deque[str] = deque(maxlen=1000)

    def ingest(self, pkt: dict) -> None:
        ts_ms = int(pkt.get("timestamp_ms", int(time.time() * 1000)))
        pkt_type = pkt.get("packet_type", "UNKNOWN")
        pid = int(pkt.get("pid", -1))
        comm = str(pkt.get("comm", "?"))
        score = float(pkt.get("risk_score", 0.0))

        dedup_key = f"{ts_ms}:{pkt_type}:{pid}:{comm}:{score:.2f}"
        with self._lock:
            if dedup_key in self._seen_keys:
                return
            self._seen_keys.append(dedup_key)

            dt_str = datetime.fromtimestamp(ts_ms / 1000.0).strftime("%H:%M:%S.%f")[:-3]
            enriched = {
                "timestamp_ms": ts_ms,
                "time_str": dt_str,
                "packet_type": pkt_type,
                "pid": pid,
                "comm": comm,
                "uid": int(pkt.get("uid", -1)),
                "risk_score": score,
                "threshold": float(pkt.get("threshold", 75.0)),
                "action_taken": str(pkt.get("action_taken", "NONE")),
                "triggered_heuristics": list(pkt.get("triggered_heuristics", [])),
                "system_metrics": dict(pkt.get("system_metrics", {})),
            }
            self.events.appendleft(enriched)

            if pkt_type == "ALERT":
                self.alert_count += 1
                if enriched["action_taken"] not in ("NONE", "LOG_ONLY", ""):
                    self.blocked_pids.add(pid)
            elif pkt_type == "METRIC":
                self.metric_count += 1
                if enriched["system_metrics"]:
                    self.latest_metrics = enriched["system_metrics"]

    def clear(self) -> None:
        with self._lock:
            self.events.clear()
            self._seen_keys.clear()
            self.alert_count = 0
            self.metric_count = 0
            self.blocked_pids.clear()
            self.latest_metrics = {}

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "alert_count": self.alert_count,
                "metric_count": self.metric_count,
                "blocked_pids": sorted(p for p in self.blocked_pids if p > 0),
                "latest_metrics": self.latest_metrics,
                "last_benchmark": self.last_benchmark,
                "last_sim_output": self.last_sim_output,
                "events": list(self.events),
            }


STORE = TelemetryStore()


def udp_worker(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
    except OSError as exc:
        print(f"[WARN] Could not bind UDP {host}:{port} ({exc}); relying on JSONL tail.", flush=True)
        sock.close()
        return

    sock.settimeout(0.5)
    print(f"[DASHBOARD] Listening for UDP telemetry on {host}:{port}", flush=True)
    while True:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        for line in data.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                STORE.ingest(json.loads(line))
            except json.JSONDecodeError:
                pass


def jsonl_worker(path: str) -> None:
    print(f"[DASHBOARD] Watching telemetry log at {path}", flush=True)
    while not os.path.exists(path):
        time.sleep(0.3)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        # Load last 50 existing entries on startup
        existing = f.readlines()[-50:]
        for line in existing:
            line = line.strip()
            if line:
                try:
                    STORE.ingest(json.loads(line))
                except json.JSONDecodeError:
                    pass

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.15)
                continue
            line = line.strip()
            if line:
                try:
                    STORE.ingest(json.loads(line))
                except json.JSONDecodeError:
                    pass


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Aegis Ransomware Detector – Live Dashboard</title>
<style>
  :root {
    --bg: #0b1120;
    --card: #111827;
    --border: #1f2937;
    --text: #f3f4f6;
    --muted: #9ca3af;
    --accent: #38bdf8;
    --danger: #ef4444;
    --warn: #f59e0b;
    --ok: #10b981;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 20px;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 14px;
    margin-bottom: 20px;
    flex-wrap: wrap;
    gap: 12px;
  }
  .title-group h1 { font-size: 1.45rem; letter-spacing: 0.3px; }
  .title-group p { color: var(--muted); font-size: 0.85rem; margin-top: 3px; }
  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: #064e3b;
    color: #6ee7b7;
    padding: 6px 12px;
    border-radius: 999px;
    font-size: 0.82rem;
    font-weight: 600;
  }
  .dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: #34d399;
    animation: pulse 1.5s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.35; }
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 14px;
    margin-bottom: 20px;
  }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
  }
  .card .label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; }
  .card .value { font-size: 1.85rem; font-weight: 700; margin-top: 6px; }
  .value.danger { color: var(--danger); }
  .value.accent { color: var(--accent); }
  .value.ok { color: var(--ok); }
  .controls {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    margin-bottom: 20px;
  }
  button {
    background: #1e293b;
    color: var(--text);
    border: 1px solid #334155;
    padding: 8px 14px;
    border-radius: 7px;
    cursor: pointer;
    font-size: 0.85rem;
    font-weight: 600;
    transition: background 0.15s;
  }
  button:hover { background: #334155; }
  button.danger-btn { background: #7f1d1d; border-color: #991b1b; }
  button.danger-btn:hover { background: #991b1b; }
  button.primary-btn { background: #0369a1; border-color: #0284c7; }
  button.primary-btn:hover { background: #0284c7; }
  .two-col {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 16px;
  }
  @media (max-width: 960px) { .two-col { grid-template-columns: 1fr; } }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.84rem;
    margin-top: 10px;
  }
  th, td {
    text-align: left;
    padding: 9px 10px;
    border-bottom: 1px solid var(--border);
  }
  th { color: var(--muted); font-weight: 600; }
  .badge {
    padding: 2px 8px;
    border-radius: 5px;
    font-size: 0.75rem;
    font-weight: 700;
  }
  .badge-alert { background: rgba(239, 68, 68, 0.2); color: #fca5a5; }
  .badge-metric { background: rgba(56, 189, 248, 0.15); color: #7dd3fc; }
  .tag {
    display: inline-block;
    background: #1f2937;
    border: 1px solid #374151;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.74rem;
    margin: 1px 3px 1px 0;
  }
  pre {
    background: #090d16;
    border: 1px solid var(--border);
    padding: 10px;
    border-radius: 6px;
    font-size: 0.78rem;
    color: #d1d5db;
    overflow-x: auto;
    margin-top: 8px;
    white-space: pre-wrap;
  }
</style>
</head>
<body>
  <header>
    <div class="title-group">
      <h1>Aegis eBPF Ransomware Detector</h1>
      <p>Live Telemetry &amp; Validation Console (UDP 127.0.0.1:51423 + JSONL Stream)</p>
    </div>
    <div class="status-pill"><span class="dot"></span> MONITORING ACTIVE</div>
  </header>

  <div class="grid">
    <div class="card">
      <div class="label">Total Alerts</div>
      <div class="value danger" id="stat-alerts">0</div>
    </div>
    <div class="card">
      <div class="label">Processes Mitigated</div>
      <div class="value accent" id="stat-blocked">0</div>
    </div>
    <div class="card">
      <div class="label">Telemetry Packets</div>
      <div class="value ok" id="stat-metrics">0</div>
    </div>
    <div class="card">
      <div class="label">Last Benchmark</div>
      <div class="value" id="stat-bench" style="font-size:1.35rem;">Not run</div>
    </div>
  </div>

  <div class="card" style="margin-bottom: 18px;">
    <div class="label" style="margin-bottom: 10px;">Validation &amp; Simulation Triggers</div>
    <div class="controls">
      <button class="danger-btn" onclick="runSim('all')">Run Full Attack Sim (--scenario all)</button>
      <button onclick="runSim('entropy')">Sim: High Entropy</button>
      <button onclick="runSim('rename')">Sim: Mass Rename</button>
      <button onclick="runSim('dag')">Sim: Sequence DAG</button>
      <button onclick="runSim('canary')">Sim: Canary Touch</button>
      <button class="primary-btn" onclick="runBenchmark()">Run Benign Benchmark</button>
      <button onclick="injectDemo()">Inject Demo Alert</button>
      <button onclick="clearFeed()">Clear Feed</button>
    </div>
    <div id="action-status" style="font-size:0.82rem; color:var(--muted);">Ready.</div>
  </div>

  <div class="two-col">
    <div class="card">
      <div class="label">Live Detection &amp; Telemetry Stream</div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Type</th>
              <th>Process (PID)</th>
              <th>Risk / Thresh</th>
              <th>Action</th>
              <th>Triggered Heuristics</th>
            </tr>
          </thead>
          <tbody id="event-rows">
            <tr><td colspan="6" style="color:var(--muted);">Waiting for telemetry packets...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div>
      <div class="card" style="margin-bottom: 16px;">
        <div class="label">Latest System Metrics</div>
        <pre id="metrics-box">No METRIC packets received yet.</pre>
      </div>
      <div class="card">
        <div class="label">Last Simulation / Benchmark Output</div>
        <pre id="output-box">No validation run triggered yet.</pre>
      </div>
    </div>
  </div>

<script>
async function fetchState() {
  try {
    const res = await fetch('/api/state');
    const data = await res.json();

    document.getElementById('stat-alerts').textContent = data.alert_count;
    document.getElementById('stat-blocked').textContent = data.blocked_pids.length;
    document.getElementById('stat-metrics').textContent = data.alert_count + data.metric_count;

    if (data.last_benchmark) {
      document.getElementById('stat-bench').textContent =
        `${data.last_benchmark.elapsed_sec}s (${data.last_benchmark.total_ops} ops)`;
    }

    if (data.latest_metrics && Object.keys(data.latest_metrics).length > 0) {
      document.getElementById('metrics-box').textContent = JSON.stringify(data.latest_metrics, null, 2);
    }

    if (data.last_sim_output) {
      document.getElementById('output-box').textContent = data.last_sim_output;
    }

    const tbody = document.getElementById('event-rows');
    if (!data.events || data.events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="color:var(--muted);">Waiting for telemetry packets...</td></tr>';
      return;
    }

    tbody.innerHTML = data.events.slice(0, 60).map(ev => {
      const isAlert = ev.packet_type === 'ALERT';
      const badgeClass = isAlert ? 'badge-alert' : 'badge-metric';
      const tags = (ev.triggered_heuristics || [])
        .map(h => `<span class="tag">${h}</span>`).join('') || '<span style="color:var(--muted);">—</span>';
      return `<tr>
        <td>${ev.time_str}</td>
        <td><span class="badge ${badgeClass}">${ev.packet_type}</span></td>
        <td><strong>${ev.comm}</strong> (${ev.pid})</td>
        <td>${ev.risk_score.toFixed(1)} / ${ev.threshold.toFixed(1)}</td>
        <td><strong>${ev.action_taken}</strong></td>
        <td>${tags}</td>
      </tr>`;
    }).join('');
  } catch (err) {
    console.error(err);
  }
}

async function runSim(scenario) {
  document.getElementById('action-status').textContent = `Running attack_sim.py --scenario ${scenario}...`;
  const res = await fetch('/api/simulate', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({scenario})
  });
  const data = await res.json();
  document.getElementById('action-status').textContent = data.status;
  fetchState();
}

async function runBenchmark() {
  document.getElementById('action-status').textContent = 'Running benign workload benchmark...';
  const res = await fetch('/api/benchmark', {method: 'POST'});
  const data = await res.json();
  document.getElementById('action-status').textContent = data.status;
  fetchState();
}

async function injectDemo() {
  await fetch('/api/demo', {method: 'POST'});
  document.getElementById('action-status').textContent = 'Injected sample telemetry alert.';
  fetchState();
}

async function clearFeed() {
  await fetch('/api/clear', {method: 'POST'});
  document.getElementById('action-status').textContent = 'Feed cleared.';
  fetchState();
}

setInterval(fetchState, 1000);
fetchState();
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return  # Keep console clean

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/api/state":
            self._send_json(STORE.snapshot())
        else:
            self._send_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {}

        if parsed.path == "/api/simulate":
            scenario = body.get("scenario", "all")
            if scenario not in ("entropy", "rename", "dag", "canary", "all"):
                self._send_json({"status": "Invalid scenario"}, status=400)
                return
            try:
                proc = subprocess.run(
                    [sys.executable, ATTACK_SIM_PATH, "--scenario", scenario, "--cleanup"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
                out = (proc.stdout + "\n" + proc.stderr).strip()
                STORE.last_sim_output = out
                self._send_json({"status": f"Completed scenario '{scenario}' (exit={proc.returncode})"})
            except Exception as exc:
                self._send_json({"status": f"Simulation failed: {exc}"}, status=500)

        elif parsed.path == "/api/benchmark":
            try:
                proc = subprocess.run(
                    [sys.executable, BENCHMARK_PATH, "--files", "30", "--iterations", "2"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                out = (proc.stdout + "\n" + proc.stderr).strip()
                STORE.last_sim_output = out
                parsed_stats = {}
                for line in out.splitlines():
                    if ":" in line and not line.startswith("["):
                        k, v = line.split(":", 1)
                        parsed_stats[k.strip()] = v.strip()
                if parsed_stats:
                    STORE.last_benchmark = parsed_stats
                self._send_json({"status": f"Benchmark complete (exit={proc.returncode})"})
            except Exception as exc:
                self._send_json({"status": f"Benchmark failed: {exc}"}, status=500)

        elif parsed.path == "/api/demo":
            STORE.ingest(
                {
                    "packet_type": "ALERT",
                    "timestamp_ms": int(time.time() * 1000),
                    "pid": 4182,
                    "comm": "attack_sim.py",
                    "uid": os.getuid() if hasattr(os, "getuid") else 1000,
                    "risk_score": 92.5,
                    "threshold": 75.0,
                    "action_taken": "SIGKILL",
                    "triggered_heuristics": [
                        "HIGH_ENTROPY_WRITE",
                        "MASS_RENAME_BURST",
                        "CANARY_TOUCH",
                    ],
                }
            )
            self._send_json({"status": "Injected demo alert"})

        elif parsed.path == "/api/clear":
            STORE.clear()
            self._send_json({"status": "Cleared"})

        else:
            self._send_json({"error": "Not found"}, status=404)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aegis Ransomware Detector Web Dashboard")
    parser.add_argument("--host", default=DEFAULT_WEB_HOST, help="Web server bind host")
    parser.add_argument("--port", type=int, default=DEFAULT_WEB_PORT, help="Web server port")
    parser.add_argument("--udp-host", default=DEFAULT_UDP_HOST, help="Telemetry UDP host")
    parser.add_argument("--udp-port", type=int, default=DEFAULT_UDP_PORT, help="Telemetry UDP port")
    parser.add_argument("--jsonl-path", default=DEFAULT_JSONL_PATH, help="Telemetry JSONL file path")
    args = parser.parse_args()

    t_udp = threading.Thread(target=udp_worker, args=(args.udp_host, args.udp_port), daemon=True)
    t_jsonl = threading.Thread(target=jsonl_worker, args=(args.jsonl_path,), daemon=True)
    t_udp.start()
    t_jsonl.start()

    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"[DASHBOARD] Web UI running at http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[DASHBOARD] Shutting down.", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
