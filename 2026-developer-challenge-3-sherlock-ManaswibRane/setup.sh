#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "[setup] Installing Python dependencies..."
pip install flask flask-cors numpy --break-system-packages --quiet 2>/dev/null || \
  pip3 install flask flask-cors numpy --break-system-packages --quiet 2>/dev/null || \
  pip install flask flask-cors numpy --quiet 2>/dev/null || true

echo "[setup] Decompressing block fixture files..."
mkdir -p fixtures
for f in fixtures/*.dat.gz; do
  if [ -f "$f" ]; then
    out="${f%.gz}"
    if [ ! -f "$out" ]; then
      echo "[setup]   Decompressing $f → $out"
      gunzip -k "$f"
    else
      echo "[setup]   Already exists: $out"
    fi
  fi
done

echo "[setup] Creating output directory..."
mkdir -p out

echo "[setup] Done."