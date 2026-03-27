#!/usr/bin/env bash
# setup.sh — Install all Python dependencies for Coin Smith
set -euo pipefail

echo "[setup] Installing Python dependencies..."

pip install \
    fastapi \
    "uvicorn[standard]" \
    python-multipart \
    pytest \
    pytest-asyncio \
    httpx \
    --break-system-packages -q

echo ""
echo "[setup] ✓ All dependencies installed."
echo ""
echo "  Run CLI:    ./cli.sh fixtures/basic_change_p2wpkh.json"
echo "  Run server: ./web.sh"
echo "  Run tests:  python -m pytest tests/ -v"
echo ""