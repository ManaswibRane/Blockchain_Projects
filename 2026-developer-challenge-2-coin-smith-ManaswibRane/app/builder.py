"""
builder.py
Core PSBT builder: orchestrates validation → coin selection → fee → PSBT → report.

This is the heart of the application. It wires together all the other modules
and produces the final JSON report.
"""

from app.validator import validate_fixture, FixtureError
from app.coin_select import select_coins, InsufficientFundsError, PolicyViolationError
from app.fee import compute_fee_and_change, estimate_vbytes
from app.locktime import compute_sequence_and_locktime
from app.psbt import build_psbt
from app.warnings import compute_warnings


def _serialise_comparison(comp: dict) -> dict:
    """Strip large 'selected' lists from comparison before JSON serialisation."""
    out = {}
    for name, v in comp.items():
        row = {k: val for k, val in v.items() if k != "selected"}
        # Replace inf with None for JSON compat
        if row.get("score") == float("inf"):
            row["score"] = None
        out[name] = row
    return out


def build_transaction(raw_fixture: dict, strategy: str = "auto") -> dict:
    """
    Build a PSBT from a raw fixture dict.

    Args:
        raw_fixture: The parsed JSON fixture (not yet validated)
        strategy: Coin selection strategy ("greedy" or "consolidate")

    Returns:
        A report dict conforming to the CLI output format spec.
        Always has "ok": True or "ok": False.
    """

    # ── Step 1: Validate fixture ─────────────────────────────────────────────
    try:
        fixture = validate_fixture(raw_fixture)
    except FixtureError as e:
        return {"ok": False, "error": {"code": e.code, "message": e.message}}
    except Exception as e:
        return {"ok": False, "error": {"code": "INVALID_FIXTURE", "message": str(e)}}

    network = fixture["network"]
    utxos = fixture["utxos"]
    payments = fixture["payments"]
    change_template = fixture["change"]
    fee_rate = fixture["fee_rate_sat_vb"]
    rbf = fixture["rbf"]
    locktime_field = fixture["locktime_field"]
    current_height = fixture["current_height"]
    max_inputs = fixture["policy"]["max_inputs"]

    # ── Step 2: Compute nSequence and nLockTime ──────────────────────────────
    try:
        n_sequence, n_lock_time, locktime_type = compute_sequence_and_locktime(
            rbf=rbf,
            locktime_field=locktime_field,
            current_height=current_height,
        )
    except Exception as e:
        return {"ok": False, "error": {"code": "INTERNAL_ERROR", "message": f"Locktime error: {e}"}}

    # ── Step 3: Select coins ─────────────────────────────────────────────────
    try:
        selected_inputs, strategy_used, strategy_comparison = select_coins(
            utxos=utxos,
            payments=payments,
            change_template=change_template,
            fee_rate_sat_vb=fee_rate,
            max_inputs=max_inputs,
            strategy=strategy,
        )
    except InsufficientFundsError as e:
        return {"ok": False, "error": {"code": "INSUFFICIENT_FUNDS", "message": str(e)}}
    except PolicyViolationError as e:
        return {"ok": False, "error": {"code": "POLICY_VIOLATION", "message": str(e)}}
    except Exception as e:
        return {"ok": False, "error": {"code": "COIN_SELECTION_ERROR", "message": str(e)}}

    # ── Step 4: Compute fee and change ───────────────────────────────────────
    try:
        fee_sats, change_value, vbytes = compute_fee_and_change(
            selected_inputs=selected_inputs,
            payments=payments,
            change_template=change_template,
            fee_rate_sat_vb=fee_rate,
        )
    except Exception as e:
        return {"ok": False, "error": {"code": "FEE_ERROR", "message": str(e)}}

    # ── Step 5: Construct output list ────────────────────────────────────────
    final_outputs = []
    for i, p in enumerate(payments):
        final_outputs.append({
            "n": i,
            "value_sats": p["value_sats"],
            "script_pubkey_hex": p["script_pubkey_hex"],
            "script_type": p["script_type"],
            "address": p["address"],
            "is_change": False,
        })

    change_index = None
    if change_value is not None:
        change_index = len(final_outputs)
        final_outputs.append({
            "n": change_index,
            "value_sats": change_value,
            "script_pubkey_hex": change_template["script_pubkey_hex"],
            "script_type": change_template["script_type"],
            "address": change_template["address"],
            "is_change": True,
        })

    # ── Step 6: Verify balance ────────────────────────────────────────────────
    total_in = sum(u["value_sats"] for u in selected_inputs)
    total_out = sum(o["value_sats"] for o in final_outputs)
    actual_fee = total_in - total_out
    if actual_fee != fee_sats:
        # Recompute actual fee from balance (more authoritative)
        fee_sats = actual_fee

    # ── Step 7: Build PSBT ────────────────────────────────────────────────────
    # Convert final_outputs to format psbt.py expects
    psbt_outputs = [
        {
            "value_sats": o["value_sats"],
            "script_pubkey_hex": o["script_pubkey_hex"],
        }
        for o in final_outputs
    ]

    try:
        psbt_b64 = build_psbt(
            selected_inputs=selected_inputs,
            final_outputs=psbt_outputs,
            n_lock_time=n_lock_time,
            n_sequence=n_sequence,
        )
    except Exception as e:
        return {"ok": False, "error": {"code": "PSBT_ERROR", "message": f"PSBT construction failed: {e}"}}

    # ── Step 8: Compute warnings ──────────────────────────────────────────────
    rbf_signaling = n_sequence <= 0xFFFFFFFD
    actual_fee_rate = round(fee_sats / vbytes, 2) if vbytes > 0 else 0.0

    warnings = compute_warnings(
        fee_sats=fee_sats,
        fee_rate_sat_vb=actual_fee_rate,
        change_value=change_value,
        rbf_signaling=rbf_signaling,
        selected_inputs=selected_inputs,
        final_outputs=final_outputs,
    )

    # ── Step 9: Assemble report ───────────────────────────────────────────────
    report = {
        "ok": True,
        "network": network,
        "strategy": strategy_used,
        "strategy_comparison": _serialise_comparison(strategy_comparison),
        "selected_inputs": selected_inputs,
        "outputs": final_outputs,
        "change_index": change_index,
        "fee_sats": fee_sats,
        "fee_rate_sat_vb": actual_fee_rate,
        "vbytes": vbytes,
        "rbf_signaling": rbf_signaling,
        "locktime": n_lock_time,
        "locktime_type": locktime_type,
        "psbt_base64": psbt_b64,
        "warnings": warnings,
    }

    return report