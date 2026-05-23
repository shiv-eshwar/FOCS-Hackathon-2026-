#!/usr/bin/env bash
set -euo pipefail

if command -v clear >/dev/null && [ -t 1 ]; then
  clear
fi

echo "[1/3] Scanning vulnerable image (expected BLOCKED)"
python3 main.py --image nginx:1.14 --output terminal --fail-on critical || true
sleep 2

if command -v clear >/dev/null && [ -t 1 ]; then
  clear
fi

echo "[2/3] Scanning newer image and generating HTML report"
python3 main.py --image nginx:latest --output html --report-file report.html --fail-on critical || true
sleep 2

if command -v clear >/dev/null && [ -t 1 ]; then
  clear
fi

echo "[3/3] Diff against baseline JSON output"
python3 main.py --image nginx:latest --output json --report-file report.json --baseline tests/fixtures/baseline_report.json --fail-on critical || true

echo "Demo complete. Open report.html in browser."
