"""
fee.py
Deterministic vbytes estimator for common Bitcoin script types.

Bitcoin transactions use a "weight" system introduced by SegWit (BIP141):
  - Non-witness data costs 4 weight units (WU) per byte
  - Witness data costs 1 weight unit per byte (discounted)
  - vbytes = ceil(total_weight / 4)

This matches what Bitcoin Core and most block explorers report.
"""
import math

# ──────────────────────────────────────────────
# Weight constants (in weight units)
# ──────────────────────────────────────────────

# Transaction overhead (non-witness):
#   nVersion(4) + vin_count(varint~1) + vout_count(varint~1) + nLockTime(4) = 10 bytes × 4 = 40 WU
# SegWit marker + flag = 2 bytes × 1 WU (witness discount) = 2 WU
# Total base = 42 WU  (applies only when ≥1 segwit input exists)
TX_OVERHEAD_LEGACY_WU = 40      # 10 bytes × 4
TX_OVERHEAD_SEGWIT_WU = 42      # 10 bytes × 4 + 2 bytes marker/flag × 1

# ── Per-input weights (non-witness portion) ──
# Every input: outpoint(36) + scriptLen(1) + sequence(4) = 41 bytes × 4 = 164 WU
INPUT_BASE_WU = 164  # txid(32)+vout(4)+scriptLen(1)+sequence(4) × 4

# Legacy P2PKH: scriptSig = OP_PUSH(1)+sig(72)+OP_PUSH(1)+pubkey(33) = 107 bytes
P2PKH_SCRIPTSIG_WU = 107 * 4   # 428

# P2SH-P2WPKH: scriptSig = OP_PUSH(1)+redeemScript(22) = 23 bytes
P2SH_P2WPKH_SCRIPTSIG_WU = 23 * 4  # 92

# SegWit inputs have empty scriptSig → 0 extra non-witness bytes

# ── Per-input witness weights (1 WU per byte) ──
# P2WPKH witness: items(1)+sig_len(1)+sig(72)+pk_len(1)+pk(33) = 108 bytes × 1 = 108 WU
P2WPKH_WITNESS_WU = 108

# P2TR key-path witness: items(1)+sig_len(1)+sig(64) = 66 bytes × 1 = 66 WU
P2TR_WITNESS_WU = 66

# P2WSH (assume 2-of-3 multisig as typical): ~250 WU estimate
P2WSH_WITNESS_WU = 250

# P2SH-P2WPKH witness: same as P2WPKH (inner key spend)
P2SH_P2WPKH_WITNESS_WU = P2WPKH_WITNESS_WU

# Legacy P2PKH has no witness
P2PKH_WITNESS_WU = 0

# ── Per-output weights ──
# Every output: value(8) + scriptLen(1) + script = 9 + script_len bytes × 4 WU
# P2PKH script: OP_DUP OP_HASH160 OP_PUSH(20) <20b> OP_EQUALVERIFY OP_CHECKSIG = 25 bytes
P2PKH_OUTPUT_WU = (8 + 1 + 25) * 4   # 136

# P2SH script: OP_HASH160 OP_PUSH(20) <20b> OP_EQUAL = 23 bytes
P2SH_OUTPUT_WU = (8 + 1 + 23) * 4    # 128

# P2WPKH script: OP_0 OP_PUSH(20) <20b> = 22 bytes
P2WPKH_OUTPUT_WU = (8 + 1 + 22) * 4  # 124

# P2WSH script: OP_0 OP_PUSH(32) <32b> = 34 bytes
P2WSH_OUTPUT_WU = (8 + 1 + 34) * 4   # 172

# P2TR script: OP_1 OP_PUSH(32) <32b> = 34 bytes
P2TR_OUTPUT_WU = (8 + 1 + 34) * 4    # 172

# ── Lookup tables ──
INPUT_NONWITNESS_WU = {
    "p2pkh":      INPUT_BASE_WU + P2PKH_SCRIPTSIG_WU,   # 592
    "p2sh":       INPUT_BASE_WU + P2PKH_SCRIPTSIG_WU,   # approximate
    "p2wpkh":     INPUT_BASE_WU,                          # 164
    "p2wsh":      INPUT_BASE_WU,                          # 164
    "p2tr":       INPUT_BASE_WU,                          # 164
    "p2sh-p2wpkh": INPUT_BASE_WU + P2SH_P2WPKH_SCRIPTSIG_WU,  # 256
}

INPUT_WITNESS_WU = {
    "p2pkh":       P2PKH_WITNESS_WU,        # 0
    "p2sh":        P2PKH_WITNESS_WU,        # 0 (approximate)
    "p2wpkh":      P2WPKH_WITNESS_WU,       # 108
    "p2wsh":       P2WSH_WITNESS_WU,        # 250
    "p2tr":        P2TR_WITNESS_WU,         # 66
    "p2sh-p2wpkh": P2SH_P2WPKH_WITNESS_WU, # 108
}

OUTPUT_WU = {
    "p2pkh":       P2PKH_OUTPUT_WU,   # 136
    "p2sh":        P2SH_OUTPUT_WU,    # 128
    "p2wpkh":      P2WPKH_OUTPUT_WU,  # 124
    "p2wsh":       P2WSH_OUTPUT_WU,   # 172
    "p2tr":        P2TR_OUTPUT_WU,    # 172
    "p2sh-p2wpkh": P2SH_OUTPUT_WU,   # 128
}

DUST_THRESHOLD = 546  # satoshis — outputs below this are "dust" and non-standard


def is_segwit_type(script_type: str) -> bool:
    return script_type in ("p2wpkh", "p2wsh", "p2tr", "p2sh-p2wpkh")


def estimate_tx_weight(
    inputs: list[dict],
    outputs: list[dict],
) -> int:
    """
    Calculate total transaction weight in weight units.

    Args:
        inputs: list of dicts with 'script_type'
        outputs: list of dicts with 'script_type'

    Returns:
        total weight in WU
    """
    has_segwit = any(is_segwit_type(i["script_type"]) for i in inputs)

    # Transaction overhead
    weight = TX_OVERHEAD_SEGWIT_WU if has_segwit else TX_OVERHEAD_LEGACY_WU

    # Inputs
    for inp in inputs:
        st = inp["script_type"]
        weight += INPUT_NONWITNESS_WU.get(st, INPUT_BASE_WU + P2PKH_SCRIPTSIG_WU)
        weight += INPUT_WITNESS_WU.get(st, 0)

    # Outputs
    for out in outputs:
        st = out["script_type"]
        # fallback: use script_pubkey_hex length if script_type unknown
        wu = OUTPUT_WU.get(st)
        if wu is None:
            spk_bytes = len(bytes.fromhex(out.get("script_pubkey_hex", "00")))
            wu = (8 + 1 + spk_bytes) * 4
        weight += wu

    return weight


def estimate_vbytes(inputs: list[dict], outputs: list[dict]) -> int:
    """Returns transaction size in vbytes (ceiled)."""
    return math.ceil(estimate_tx_weight(inputs, outputs) / 4)


def required_fee(inputs: list[dict], outputs: list[dict], fee_rate_sat_vb: float) -> int:
    """Returns minimum required fee in satoshis (ceiled to nearest sat). Always >= 0."""
    if fee_rate_sat_vb < 0:
        raise ValueError(f"fee_rate_sat_vb cannot be negative (got {fee_rate_sat_vb})")
    vbytes = estimate_vbytes(inputs, outputs)
    return max(0, math.ceil(vbytes * fee_rate_sat_vb))


def compute_fee_and_change(
    selected_inputs: list[dict],
    payments: list[dict],
    change_template: dict,
    fee_rate_sat_vb: float,
) -> tuple[int, int | None, int]:
    """
    Two-pass fee + change computation.

    Returns:
        (fee_sats, change_value_or_None, vbytes)

    Logic:
    1. Estimate fee WITHOUT change output.
    2. Compute leftover = sum(inputs) - sum(payments) - fee_no_change.
    3. If leftover < DUST_THRESHOLD → no change (SEND_ALL), fee absorbs leftover.
    4. Else estimate fee WITH change output.
    5. Compute change_value = sum(inputs) - sum(payments) - fee_with_change.
    6. If change_value < DUST_THRESHOLD → no change (SEND_ALL).
    7. Else → create change output.
    """
    total_in = sum(u["value_sats"] for u in selected_inputs)
    total_out = sum(p["value_sats"] for p in payments)

    # Guard: outputs can never exceed inputs (would be an invalid transaction)
    if total_out > total_in:
        raise ValueError(
            f"Payments ({total_out} sats) exceed total inputs ({total_in} sats). "
            f"This transaction is impossible."
        )

    # Pass 1: without change
    fee_no_change = required_fee(selected_inputs, payments, fee_rate_sat_vb)
    leftover = total_in - total_out - fee_no_change
    vbytes_no_change = estimate_vbytes(selected_inputs, payments)

    if leftover < DUST_THRESHOLD:
        # Absorb leftover into fee (SEND_ALL)
        actual_fee = total_in - total_out  # fee = everything left over
        if actual_fee < 0:
            raise ValueError(f"Fee would be negative ({actual_fee} sats). Inputs do not cover outputs.")
        return actual_fee, None, vbytes_no_change

    # Pass 2: with change output
    outputs_with_change = payments + [change_template]
    fee_with_change = required_fee(selected_inputs, outputs_with_change, fee_rate_sat_vb)
    change_value = total_in - total_out - fee_with_change

    if change_value < DUST_THRESHOLD:
        # Change would be dust → drop it, absorb into fee
        actual_fee = total_in - total_out
        if actual_fee < 0:
            raise ValueError(f"Fee would be negative ({actual_fee} sats). Inputs do not cover outputs.")
        return actual_fee, None, vbytes_no_change

    vbytes_with_change = estimate_vbytes(selected_inputs, outputs_with_change)
    return fee_with_change, change_value, vbytes_with_change