#!/usr/bin/env bash
# cli.sh <fixture.json>
#
# Reads the fixture file, runs the PSBT builder, writes the JSON report to
# out/<fixture_name>.json  (directory created if it doesn't exist).
#
# Logs go to stderr.
# Exit 0 on success, 1 on any error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 1 ]]; then
    echo '[coin-smith] ERROR: Usage: ./cli.sh <fixture.json>' >&2
    exit 1
fi

FIXTURE_PATH="$1"

if [[ ! -f "$FIXTURE_PATH" ]]; then
    echo "[coin-smith] ERROR: File not found: $FIXTURE_PATH" >&2
    exit 1
fi

cd "$SCRIPT_DIR"
python3 main.py "$FIXTURE_PATH"