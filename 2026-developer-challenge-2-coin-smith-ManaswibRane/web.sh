#!/usr/bin/env bash
# web.sh
#
# Starts the Coin Smith FastAPI web application using uvicorn.
# Prints "http://127.0.0.1:<PORT>" to stdout (required by spec).
# Keeps running until terminated (Ctrl+C).
# Honors PORT env var (default 3000).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${PORT:-3000}"

# Print URL to stdout — required by the spec evaluator
echo "http://127.0.0.1:${PORT}"

# Start uvicorn with the FastAPI app
# app.api:app  →  app/api.py  →  FastAPI instance named `app`
exec python3 -m uvicorn app.api:app \
    --host 0.0.0.0 \
    --port "${PORT}" \
    --no-access-log \
    --log-level critical \
    2>/dev/null