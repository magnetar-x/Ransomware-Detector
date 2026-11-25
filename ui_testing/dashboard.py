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
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
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
<title>eBPF Ransomware Detector – Live Dashboard</title>
<style>
  :root {
    --bg: #080412;
    --card: rgba(25, 13, 48, 0.52);
    --card-inner: rgba(13, 6, 28, 0.56);
    --border: rgba(192, 132, 252, 0.25);
    --border-gold: rgba(250, 204, 21, 0.45);
    --text: #faf5ff;
    --muted: #c4b5fd;
    --purple: #a855f7;
    --purple-bright: #c084fc;
    --yellow: #facc15;
    --yellow-bright: #fde047;
    --danger: #fb7185;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background-color: var(--bg);
    background-image:
      radial-gradient(circle at 14% 18%, rgba(168, 85, 247, 0.34) 0%, transparent 42%),
      radial-gradient(circle at 86% 12%, rgba(250, 204, 21, 0.18) 0%, transparent 38%),
      radial-gradient(circle at 52% 88%, rgba(126, 34, 206, 0.28) 0%, transparent 48%),
      linear-gradient(rgba(168, 85, 247, 0.05) 1px, transparent 1px),
      linear-gradient(90deg, rgba(250, 204, 21, 0.04) 1px, transparent 1px);
    background-size: 100% 100%, 100% 100%, 100% 100%, 36px 36px, 36px 36px;
    background-attachment: fixed;
    color: var(--text);
    padding: 22px;
    min-height: 100vh;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--card);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 16px 20px;
    margin-bottom: 20px;
    flex-wrap: wrap;
    gap: 12px;
    box-shadow: 0 8px 32px rgba(8, 4, 18, 0.55), inset 0 1px 0 rgba(250, 204, 21, 0.12);
  }
  .title-group h1 {
    font-size: 1.5rem;
    letter-spacing: 0.6px;
    background: linear-gradient(90deg, var(--yellow-bright), var(--purple-bright));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .title-group p { color: var(--muted); font-size: 0.84rem; margin-top: 4px; opacity: 0.88; }
  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(250, 204, 21, 0.12);
    border: 1px solid rgba(250, 204, 21, 0.4);
    color: var(--yellow-bright);
    padding: 7px 14px;
    border-radius: 999px;
    font-size: 0.8rem;
    font-weight: 700;
    letter-spacing: 0.6px;
    backdrop-filter: blur(10px);
  }
  .dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--yellow);
    box-shadow: 0 0 10px var(--yellow);
    animation: pulse 1.5s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.85); }
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 20px;
  }
  .card {
    background: var(--card);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px;
    box-shadow: 0 8px 30px rgba(6, 2, 16, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.06);
    position: relative;
  }
  .card .label {
    color: var(--muted);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    font-weight: 600;
  }
  .card .value {
    font-size: 2.1rem;
    font-weight: 800;
    margin-top: 12px;
    font-variant-numeric: tabular-nums;
  }
  .value.danger { color: var(--danger); text-shadow: 0 0 16px rgba(251, 113, 133, 0.3); }
  .value.accent { color: var(--purple-bright); text-shadow: 0 0 16px rgba(192, 132, 252, 0.3); }
  .gauge-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
  }
  .gauge-card .label { width: 100%; text-align: left; margin-bottom: 4px; }
  .gauge-wrap {
    width: 100%;
    max-width: 210px;
    position: relative;
  }
  .gauge-svg { width: 100%; height: auto; display: block; overflow: visible; }
  .gauge-needle {
    transform-origin: 100px 96px;
    transition: transform 0.55s cubic-bezier(0.22, 1, 0.36, 1);
  }
  .gauge-arc-fill {
    transition: stroke-dashoffset 0.55s cubic-bezier(0.22, 1, 0.36, 1);
  }
  .gauge-readout {
    margin-top: -12px;
    font-size: 1.45rem;
    font-weight: 800;
    color: var(--yellow-bright);
    font-variant-numeric: tabular-nums;
    text-shadow: 0 0 14px rgba(250, 204, 21, 0.35);
  }
  .gauge-sub {
    margin-top: 2px;
    font-size: 0.76rem;
    color: var(--muted);
    font-variant-numeric: tabular-nums;
  }
  .controls {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    margin-bottom: 14px;
  }
  button {
    background: rgba(59, 28, 107, 0.5);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    color: var(--text);
    border: 1px solid rgba(192, 132, 252, 0.32);
    padding: 9px 14px;
    border-radius: 9px;
    cursor: pointer;
    font-size: 0.84rem;
    font-weight: 600;
    transition: all 0.18s ease;
  }
  button:hover {
    background: rgba(126, 34, 206, 0.62);
    border-color: rgba(250, 204, 21, 0.55);
    transform: translateY(-1px);
  }
  button.danger-btn {
    background: rgba(136, 19, 55, 0.52);
    border-color: rgba(251, 113, 133, 0.45);
  }
  button.danger-btn:hover { background: rgba(159, 18, 57, 0.72); }
  button.primary-btn {
    background: rgba(107, 33, 168, 0.58);
    border-color: rgba(192, 132, 252, 0.55);
  }
  button.primary-btn:hover { background: rgba(126, 34, 206, 0.78); }
  button.active-trigger {
    background: linear-gradient(135deg, #facc15, #eab308);
    color: #140726;
    border-color: #fef08a;
    box-shadow: 0 0 18px rgba(250, 204, 21, 0.48);
  }
  button.active-trigger:hover {
    background: linear-gradient(135deg, #fde047, #facc15);
    color: #140726;
  }
  .trigger-status-bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
    font-size: 0.82rem;
    color: var(--muted);
  }
  .selected-trigger-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(250, 204, 21, 0.14);
    border: 1px solid rgba(250, 204, 21, 0.45);
    color: var(--yellow-bright);
    padding: 4px 10px;
    border-radius: 999px;
    font-weight: 700;
    font-size: 0.78rem;
  }
  .selected-trigger-pill.idle {
    background: rgba(168, 85, 247, 0.16);
    border-color: rgba(192, 132, 252, 0.3);
    color: var(--muted);
  }
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
    border-bottom: 1px solid rgba(192, 132, 252, 0.16);
  }
  th { color: var(--yellow); font-weight: 700; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge {
    padding: 2px 8px;
    border-radius: 5px;
    font-size: 0.75rem;
    font-weight: 700;
  }
  .badge-alert { background: rgba(251, 113, 133, 0.2); color: #fda4af; border: 1px solid rgba(251, 113, 133, 0.35); }
  .badge-metric { background: rgba(168, 85, 247, 0.22); color: #e9d5ff; border: 1px solid rgba(192, 132, 252, 0.35); }
  .tag {
    display: inline-block;
    background: rgba(127, 29, 29, 0.35);
    border: 1px solid rgba(248, 113, 113, 0.45);
    color: #f87171;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.74rem;
    font-weight: 600;
    margin: 1px 3px 1px 0;
  }
  .none-heuristic {
    color: #34d399;
    font-weight: 600;
  }
  pre {
    background: var(--card-inner);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    border: 1px solid rgba(192, 132, 252, 0.2);
    padding: 12px;
    border-radius: 8px;
    font-size: 0.78rem;
    color: #ede9fe;
    overflow-x: auto;
    margin-top: 8px;
    white-space: pre-wrap;
  }
</style>
</head>
<body>
  <header>
    <div class="title-group">
      <h1>eBPF Ransomware Detector</h1>
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
    <div class="card gauge-card">
      <div class="label">Telemetry Packets</div>
      <div class="gauge-wrap">
        <svg class="gauge-svg" viewBox="0 0 200 120" aria-label="Telemetry Packets Gauge">
          <defs>
            <linearGradient id="sciGrad1" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stop-color="#a855f7" />
              <stop offset="100%" stop-color="#facc15" />
            </linearGradient>
          </defs>
          <path d="M 24 96 A 76 76 0 1 1 176 96" fill="none" stroke="rgba(192,132,252,0.18)" stroke-width="11" stroke-linecap="round" />
          <path id="pkt-arc" class="gauge-arc-fill" d="M 24 96 A 76 76 0 1 1 176 96" fill="none" stroke="url(#sciGrad1)" stroke-width="11" stroke-linecap="round" stroke-dasharray="238.76" stroke-dashoffset="238.76" />
          <g id="pkt-needle" class="gauge-needle" style="transform: rotate(-90deg);">
            <line x1="100" y1="96" x2="100" y2="30" stroke="#fde047" stroke-width="3" stroke-linecap="round" />
          </g>
          <circle cx="100" cy="96" r="6" fill="#facc15" stroke="#2e1065" stroke-width="2" />
          <text x="18" y="114" fill="#c4b5fd" font-size="9">0</text>
          <text x="182" y="114" fill="#fde047" font-size="9" text-anchor="end" id="pkt-scale-max">100</text>
        </svg>
        <div class="gauge-readout" id="stat-metrics">0</div>
        <div class="gauge-sub" id="pkt-sub">0 events/sec</div>
      </div>
    </div>
    <div class="card gauge-card">
      <div class="label">Last Benchmark</div>
      <div class="gauge-wrap">
        <svg class="gauge-svg" viewBox="0 0 200 120" aria-label="Benchmark Speedometer Gauge">
          <defs>
            <linearGradient id="sciGrad2" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stop-color="#9333ea" />
              <stop offset="100%" stop-color="#fde047" />
            </linearGradient>
          </defs>
          <path d="M 24 96 A 76 76 0 1 1 176 96" fill="none" stroke="rgba(192,132,252,0.18)" stroke-width="11" stroke-linecap="round" />
          <path id="bench-arc" class="gauge-arc-fill" d="M 24 96 A 76 76 0 1 1 176 96" fill="none" stroke="url(#sciGrad2)" stroke-width="11" stroke-linecap="round" stroke-dasharray="238.76" stroke-dashoffset="238.76" />
          <g id="bench-needle" class="gauge-needle" style="transform: rotate(-90deg);">
            <line x1="100" y1="96" x2="100" y2="30" stroke="#fde047" stroke-width="3" stroke-linecap="round" />
          </g>
          <circle cx="100" cy="96" r="6" fill="#facc15" stroke="#2e1065" stroke-width="2" />
          <text x="18" y="114" fill="#c4b5fd" font-size="9">0</text>
          <text x="182" y="114" fill="#fde047" font-size="9" text-anchor="end">20k ops/s</text>
        </svg>
        <div class="gauge-readout" id="stat-bench" style="font-size:1.1rem;">Not run</div>
        <div class="gauge-sub" id="bench-sub">Run benign benchmark</div>
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom: 18px;">
    <div class="label" style="margin-bottom: 10px;">Validation &amp; Simulation Triggers</div>
    <div class="controls">
      <button class="danger-btn trigger-btn" data-label="Full Attack Sim (all)" onclick="selectTrigger(this); runSim('all')">Run Full Attack Sim (--scenario all)</button>
      <button class="trigger-btn" data-label="Sim: High Entropy" onclick="selectTrigger(this); runSim('entropy')">Sim: High Entropy</button>
      <button class="trigger-btn" data-label="Sim: Mass Rename" onclick="selectTrigger(this); runSim('rename')">Sim: Mass Rename</button>
      <button class="trigger-btn" data-label="Sim: Sequence DAG" onclick="selectTrigger(this); runSim('dag')">Sim: Sequence DAG</button>
      <button class="trigger-btn" data-label="Sim: Canary Touch" onclick="selectTrigger(this); runSim('canary')">Sim: Canary Touch</button>
      <button class="primary-btn trigger-btn" data-label="Benign Benchmark" onclick="selectTrigger(this); runBenchmark()">Run Benign Benchmark</button>
      <button class="trigger-btn" data-label="Inject Demo Alert" onclick="selectTrigger(this); injectDemo()">Inject Demo Alert</button>
      <button class="trigger-btn" data-label="Clear Feed" onclick="selectTrigger(this); clearFeed()">Clear Feed</button>
    </div>
    <div class="trigger-status-bar">
      <span class="selected-trigger-pill idle" id="selected-trigger-pill">Selected Trigger: None</span>
      <span id="action-status">Ready.</span>
    </div>
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
const ARC_LEN = 238.76;

function escapeHtml(val) {
  return String(val ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function setGauge(arcId, needleId, ratio) {
  const clamped = Math.max(0, Math.min(1, ratio));
  const arc = document.getElementById(arcId);
  const needle = document.getElementById(needleId);
  if (arc) {
    arc.style.strokeDashoffset = (ARC_LEN * (1 - clamped)).toFixed(2);
  }
  if (needle) {
    const deg = -90 + clamped * 180;
    needle.style.transform = `rotate(${deg.toFixed(1)}deg)`;
  }
}

function selectTrigger(btn) {
  document.querySelectorAll('.trigger-btn').forEach(b => b.classList.remove('active-trigger'));
  if (btn) {
    btn.classList.add('active-trigger');
    const label = btn.dataset.label || btn.textContent.trim();
    const pill = document.getElementById('selected-trigger-pill');
    pill.classList.remove('idle');
    pill.textContent = `Selected Trigger: ${label}`;
  }
}

async function fetchState() {
  try {
    const res = await fetch('/api/state');
    const data = await res.json();

    const totalPackets = data.alert_count + data.metric_count;
    document.getElementById('stat-alerts').textContent = data.alert_count;
    document.getElementById('stat-blocked').textContent = data.blocked_pids.length;
    document.getElementById('stat-metrics').textContent = totalPackets;

    // Auto-scale telemetry packet speedometer cleanly
    const pktMax = totalPackets <= 100 ? 100 : totalPackets <= 500 ? 500 : totalPackets <= 2000 ? 2000 : Math.ceil(totalPackets / 1000) * 1000;
    document.getElementById('pkt-scale-max').textContent = pktMax;
    setGauge('pkt-arc', 'pkt-needle', totalPackets / pktMax);
    const eps = data.latest_metrics && data.latest_metrics.events_per_sec !== undefined ? data.latest_metrics.events_per_sec : 0;
    document.getElementById('pkt-sub').textContent = `${eps} events/sec`;

    if (data.last_benchmark) {
      const elapsed = parseFloat(data.last_benchmark.elapsed_sec) || 0;
      const totalOps = parseInt(data.last_benchmark.total_ops, 10) || 0;
      const opsPerSec = elapsed > 0 ? Math.round(totalOps / elapsed) : 0;
      document.getElementById('stat-bench').textContent = `${data.last_benchmark.elapsed_sec}s (${totalOps} ops)`;
      document.getElementById('bench-sub').textContent = `${opsPerSec.toLocaleString()} ops/sec`;
      setGauge('bench-arc', 'bench-needle', opsPerSec / 20000);
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
      const heuristics = ev.triggered_heuristics || [];
      const tags = heuristics.length > 0
        ? heuristics.map(h => `<span class="tag">${escapeHtml(h)}</span>`).join('')
        : '<span class="none-heuristic">None</span>';
      return `<tr>
        <td>${escapeHtml(ev.time_str)}</td>
        <td><span class="badge ${badgeClass}">${escapeHtml(ev.packet_type)}</span></td>
        <td><strong>${escapeHtml(ev.comm)}</strong> (${escapeHtml(ev.pid)})</td>
        <td>${Number(ev.risk_score).toFixed(1)} / ${Number(ev.threshold).toFixed(1)}</td>
        <td><strong>${escapeHtml(ev.action_taken)}</strong></td>
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
                    "system_metrics": {},
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
    parser.add_argument("--mock", action="store_true", help="Also launch the detection engine in --mock --dry-run mode")
    parser.add_argument("--scenario", default="mixed", help="Mock scenario when --mock is enabled")
    parser.add_argument("--events-per-sec", type=int, default=500, help="Mock event throughput when --mock is enabled")
    args = parser.parse_args()

    t_udp = threading.Thread(target=udp_worker, args=(args.udp_host, args.udp_port), daemon=True)
    t_jsonl = threading.Thread(target=jsonl_worker, args=(args.jsonl_path,), daemon=True)
    t_udp.start()
    t_jsonl.start()

    mock_proc: subprocess.Popen | None = None
    if args.mock:
        mock_proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "engine.main_daemon",
                "--mock",
                "--dry-run",
                "--scenario",
                args.scenario,
                "--events-per-sec",
                str(args.events_per_sec),
                "--udp-port",
                str(args.udp_port),
                "--log-file",
                args.jsonl_path,
            ],
            cwd=REPO_ROOT,
        )
        print(f"[DASHBOARD] Started mock engine daemon (pid={mock_proc.pid}, scenario={args.scenario})", flush=True)

    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"[DASHBOARD] Web UI running at http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[DASHBOARD] Shutting down.", flush=True)
    finally:
        server.server_close()
        if mock_proc is not None and mock_proc.poll() is None:
            mock_proc.terminate()
            try:
                mock_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                mock_proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
