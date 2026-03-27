#!/usr/bin/env bash
cd "$(dirname "$0")"
PORT="${PORT:-3000}"
export PORT
echo "http://127.0.0.1:${PORT}"
exec python3 web.py >/dev/null 2>&1