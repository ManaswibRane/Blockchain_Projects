#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
 
if [ "$1" != "--block" ] || [ $# -lt 4 ]; then
  echo '{"ok":false,"error":{"code":"INVALID_ARGS","message":"Usage: ./cli.sh --block <blk.dat> <rev.dat> <xor.dat>"}}'
  exit 1
fi
 
python3 cli.py --block "$2" "$3" "$4"