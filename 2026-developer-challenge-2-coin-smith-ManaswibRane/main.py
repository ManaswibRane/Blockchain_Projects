"""
main.py
CLI entry point for the Coin Smith PSBT builder.

Usage:
    python main.py <fixture.json>

Writes:
    out/<fixture_name>.json   — JSON report
    stderr                    — progress / error logs

Exit codes:
    0   success
    1   error  (invalid fixture, insufficient funds, etc.)
"""

import sys
import os
import json

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.builder import build_transaction


def main() -> None:
    # ── Argument check ────────────────────────────────────────────────────────
    if len(sys.argv) < 2:
        _write_err_and_exit(
            "MISSING_ARGUMENT",
            "Usage: python main.py <fixture.json>",
        )

    fixture_path = sys.argv[1]

    # ── File existence check ──────────────────────────────────────────────────
    if not os.path.isfile(fixture_path):
        _write_err_and_exit(
            "FILE_NOT_FOUND",
            f"Fixture file not found: {fixture_path}",
        )

    # ── Parse JSON ────────────────────────────────────────────────────────────
    try:
        with open(fixture_path, "r", encoding="utf-8") as fh:
            raw_fixture = json.load(fh)
    except json.JSONDecodeError as exc:
        _write_err_and_exit("INVALID_JSON", f"Failed to parse fixture: {exc}")
    except OSError as exc:
        _write_err_and_exit("READ_ERROR", str(exc))

    # ── Build ─────────────────────────────────────────────────────────────────
    _log(f"Building PSBT for: {fixture_path}")
    report = build_transaction(raw_fixture, strategy="greedy")

    # ── Determine output path ─────────────────────────────────────────────────
    # fixtures/basic_change_p2wpkh.json  →  out/basic_change_p2wpkh.json
    fixture_basename = os.path.basename(fixture_path)        # basic_change_p2wpkh.json
    fixture_stem     = os.path.splitext(fixture_basename)[0] # basic_change_p2wpkh

    project_root = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(project_root, "out")
    os.makedirs(out_dir, exist_ok=True)

    out_path = os.path.join(out_dir, f"{fixture_stem}.json")

    # ── Write output ──────────────────────────────────────────────────────────
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    except OSError as exc:
        _log(f"ERROR: Failed to write output: {exc}")
        sys.exit(1)

    # ── Exit ──────────────────────────────────────────────────────────────────
    if report.get("ok"):
        _log(f"OK → {out_path}")
        _log(
            f"Fee: {report['fee_sats']} sats  |  "
            f"Rate: {report['fee_rate_sat_vb']} sat/vbyte  |  "
            f"Size: {report['vbytes']} vbytes  |  "
            f"Inputs: {len(report['selected_inputs'])}  |  "
            f"Outputs: {len(report['outputs'])}"
        )
        if report.get("warnings"):
            codes = [w["code"] for w in report["warnings"]]
            _log(f"Warnings: {', '.join(codes)}")
        sys.exit(0)
    else:
        err = report.get("error", {})
        _log(f"ERROR [{err.get('code', '?')}]: {err.get('message', '?')}")
        sys.exit(1)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    """Write a log line to stderr (keeps stdout clean for piping)."""
    print(f"[coin-smith] {msg}", file=sys.stderr)


def _write_err_and_exit(code: str, message: str) -> None:
    """Write error JSON to stderr and exit with code 1."""
    payload = {"ok": False, "error": {"code": code, "message": message}}
    print(json.dumps(payload), file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()