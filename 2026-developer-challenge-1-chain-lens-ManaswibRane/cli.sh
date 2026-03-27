#!/usr/bin/env bash

# Resolve the directory containing this script (project root)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Create out/ directory
mkdir -p out

# Find Python (Windows Git Bash may only have "python", not "python3")
if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    printf '{"ok":false,"error":{"code":"NO_PYTHON","message":"Python 3 not found in PATH"}}\n'
    exit 1
fi

"$PY" cli/main.py "$@"
exit $?