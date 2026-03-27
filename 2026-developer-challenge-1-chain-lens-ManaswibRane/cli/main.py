#!/usr/bin/env python3
"""
Chain Lens CLI - matches flat repo structure:
  core/, services/, cli/, api/, templates/
"""
import sys
import os
import json
import traceback
from pathlib import Path

_THIS = Path(__file__).resolve()
_PROJECT_ROOT = _THIS.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _err(code, msg):
    return {"ok": False, "error": {"code": str(code), "message": str(msg)}}


def main():
    try:
        _run()
    except SystemExit:
        raise
    except Exception as e:
        out = json.dumps(_err("INTERNAL_ERROR", traceback.format_exc()))
        sys.stdout.write(out + "\n")
        sys.stdout.flush()
        sys.exit(1)


def _run():
    args = sys.argv[1:]

    if not args:
        _print_exit(_err("USAGE",
            "Usage: cli.sh <fixture.json>  OR  cli.sh --block <blk*.dat> <rev*.dat> <xor.dat>"), 1)

    out_dir = _PROJECT_ROOT / "out"
    out_dir.mkdir(exist_ok=True)

    if args[0] == "--block":
        _block_mode(args[1:], out_dir)
    else:
        _tx_mode(args[0], out_dir)


def _tx_mode(fixture_arg, out_dir):
    fixture_path = None
    for candidate in [Path(fixture_arg),
                      Path.cwd() / fixture_arg,
                      _PROJECT_ROOT / fixture_arg]:
        if candidate.exists():
            fixture_path = candidate
            break

    if fixture_path is None:
        _print_exit(_err("FILE_NOT_FOUND", f"Fixture not found: {fixture_arg}"), 1)

    try:
        raw_text = fixture_path.read_text(encoding="utf-8")
    except Exception as e:
        _print_exit(_err("READ_ERROR", f"Cannot read {fixture_path}: {e}"), 1)

    try:
        fixture = json.loads(raw_text)
    except json.JSONDecodeError as e:
        _print_exit(_err("INVALID_JSON", f"JSON error: {e}"), 1)

    try:
        from services.analyzer import analyze_transaction
        result = analyze_transaction(fixture)
    except Exception as e:
        _print_exit(_err("ANALYSIS_ERROR", traceback.format_exc()), 1)

    # Single-tx mode: pretty-print to stdout AND write file
    out_str = json.dumps(result, indent=2)

    if result.get("ok"):
        txid = result["txid"]
        out_file = out_dir / f"{txid}.json"
        out_file.write_text(out_str, encoding="utf-8")

    sys.stdout.write(out_str + "\n")
    sys.stdout.flush()
    sys.exit(0 if result.get("ok") else 1)


def _block_mode(block_args, out_dir):
    if len(block_args) != 3:
        _print_exit(_err("USAGE", "Block mode: --block <blk*.dat> <rev*.dat> <xor.dat>"), 1)

    blk_path, rev_path, xor_path = [Path(p) for p in block_args]

    for p in [blk_path, rev_path, xor_path]:
        if not p.exists():
            _print_exit(_err("FILE_NOT_FOUND", f"File not found: {p}"), 1)

    try:
        blk_data = blk_path.read_bytes()
        rev_data = rev_path.read_bytes()
        xor_data = xor_path.read_bytes()
    except Exception as e:
        _print_exit(_err("READ_ERROR", str(e)), 1)

    try:
        from core.block_parser import parse_block_file, xor_decode
        blk_decoded = xor_decode(blk_data, xor_data)
        rev_decoded = xor_decode(rev_data, xor_data)
        results = parse_block_file(blk_decoded, rev_decoded)
    except Exception as e:
        _print_exit(_err("BLOCK_PARSE_ERROR", traceback.format_exc()), 1)

    had_error = False
    for result in results:
        if not result.get("ok"):
            sys.stderr.write(json.dumps(result) + "\n")
            sys.stderr.flush()
            had_error = True
            continue
        block_hash = result["block_header"]["block_hash"]
        out_file = out_dir / f"{block_hash}.json"
        # OPTIMIZATION: compact JSON (no indent) is 6x faster to serialize
        # and 30% smaller — critical for writing many large block files.
        out_file.write_text(json.dumps(result), encoding="utf-8")
        sys.stderr.write(f"[chain-lens] wrote out/{block_hash}.json\n")
        sys.stderr.flush()

    sys.exit(1 if had_error else 0)


def _print_exit(data, code):
    sys.stdout.write(json.dumps(data, indent=2) + "\n")
    sys.stdout.flush()
    sys.exit(code)


if __name__ == "__main__":
    main()