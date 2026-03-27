#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# setup.sh — Install project dependencies
###############################################################################

# Install jq if not present
if ! command -v jq &> /dev/null; then
  echo "Installing jq..."
  sudo apt-get update
  sudo apt-get install -y jq
fi

# Decompress block fixtures if not already present
for gz in fixtures/blocks/*.dat.gz; do
  dat="${gz%.gz}"
  if [[ ! -f "$dat" ]]; then
    echo "Decompressing $(basename "$gz")..."
    gunzip -k "$gz"
  fi
done

echo "Setup complete"