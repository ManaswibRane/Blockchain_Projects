#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${PORT:-3000}"

if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo '{"ok":false,"error":{"code":"NO_PYTHON","message":"Python 3 not found"}}'
    exit 1
fi

echo "http://127.0.0.1:${PORT}"

exec "$PY" api/server.py