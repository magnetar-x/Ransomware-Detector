# UI & Validation Test Report — Ransomware Detector

## Environment
- **Host / OS:** Linux VirtualBox VM (Lubuntu)
- **Telemetry Endpoint:** UDP `127.0.0.1:51423` & `/tmp/aegis_telemetry.jsonl`
- **Dashboard URL:** `http://127.0.0.1:8080`

## Benign Workload Benchmark (`ui_testing/benchmark.py`)
Command:

```bash
python3 ui_testing/benchmark.py --files 30 --iterations 2
