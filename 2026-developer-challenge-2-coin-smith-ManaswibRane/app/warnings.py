"""
warnings.py
Emit structured warning codes for the JSON report.

Warnings inform the user (and evaluators) about unusual or risky
properties of the constructed transaction. They do NOT prevent
the transaction from being built — they are advisory.
"""

HIGH_FEE_SATS_THRESHOLD = 1_000_000    # 0.01 BTC
HIGH_FEE_RATE_THRESHOLD = 200.0         # sat/vbyte
DUST_THRESHOLD = 546                    # satoshis


def compute_warnings(
    fee_sats: int,
    fee_rate_sat_vb: float,
    change_value: int | None,
    rbf_signaling: bool,
    selected_inputs: list[dict],
    final_outputs: list[dict],
) -> list[dict]:
    """
    Evaluate transaction properties and return a list of warning dicts.

    Each warning has at minimum {"code": "..."} and optionally "message".

    Warning codes:
      HIGH_FEE       — fee is unusually large (protects against mistakes)
      DUST_CHANGE    — change output exists but is below dust threshold
      SEND_ALL       — no change output; all leftover became fee
      RBF_SIGNALING  — transaction opts into Replace-By-Fee
    """
    warnings = []

    # HIGH_FEE: fee is > 1M sats OR fee rate > 200 sat/vbyte
    if fee_sats > HIGH_FEE_SATS_THRESHOLD or fee_rate_sat_vb > HIGH_FEE_RATE_THRESHOLD:
        warnings.append({
            "code": "HIGH_FEE",
            "message": (
                f"Fee is {fee_sats} sats at {fee_rate_sat_vb:.2f} sat/vbyte. "
                f"This is unusually high — verify before broadcasting."
            ),
        })

    # DUST_CHANGE: a change output exists but is below dust threshold
    # (This shouldn't happen if fee.py works correctly, but we warn defensively)
    if change_value is not None and change_value < DUST_THRESHOLD:
        warnings.append({
            "code": "DUST_CHANGE",
            "message": (
                f"Change output is {change_value} sats, below the dust threshold "
                f"of {DUST_THRESHOLD} sats. This output may not be accepted by nodes."
            ),
        })

    # SEND_ALL: no change output was created; leftover consumed as fee
    if change_value is None:
        warnings.append({
            "code": "SEND_ALL",
            "message": (
                "No change output was created. All remaining funds after payments "
                "were absorbed as transaction fee. Verify this is intentional."
            ),
        })

    # RBF_SIGNALING: transaction opts into Replace-By-Fee
    if rbf_signaling:
        warnings.append({
            "code": "RBF_SIGNALING",
            "message": (
                "This transaction signals Replace-By-Fee (BIP-125). "
                "It can be replaced in the mempool by a higher-fee version "
                "before confirmation."
            ),
        })

    return warnings