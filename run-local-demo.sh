#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

IMAGE_TAG="vaultshield-app:fixed-demo"
REPORTS_DIR="reports"

echo "[1/4] Building fixed VaultShield image..."
docker build -t "${IMAGE_TAG}" .

echo "[2/4] Running scanner gate..."
python3 main.py \
  --image "${IMAGE_TAG}" \
  --output both \
  --reports-dir "${REPORTS_DIR}" \
  --fail-on critical \
  --project "VaultShield Demo App" \
  --branch "local-demo" || true

echo "[3/4] Running container on http://localhost:8080 ..."
docker rm -f vaultshield-local-demo >/dev/null 2>&1 || true
docker run -d --name vaultshield-local-demo -p 8080:80 "${IMAGE_TAG}" >/dev/null

echo "[4/4] Opening browser (if supported) ..."
if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "http://localhost:8080" >/dev/null 2>&1 || true
fi

echo "Local demo ready."
echo "- Landing page: http://localhost:8080"
echo "- Reports: ${REPORTS_DIR}/report.json and ${REPORTS_DIR}/report.html"
