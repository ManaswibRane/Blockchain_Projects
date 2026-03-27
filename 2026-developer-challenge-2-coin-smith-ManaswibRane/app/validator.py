"""
validator.py
Defensive fixture parsing. Rejects malformed input with structured errors.
"""

VALID_SCRIPT_TYPES = {"p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2tr", "p2sh-p2wpkh"}
VALID_NETWORKS = {"mainnet", "testnet", "signet", "regtest"}


class FixtureError(Exception):
    """Raised when a fixture fails validation."""
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def _require(condition: bool, code: str, message: str):
    if not condition:
        raise FixtureError(code, message)


def _validate_hex(value: str, field: str) -> str:
    """Ensure a string is valid hex."""
    _require(isinstance(value, str), "INVALID_FIXTURE", f"{field} must be a string")
    try:
        bytes.fromhex(value)
    except ValueError:
        raise FixtureError("INVALID_FIXTURE", f"{field} is not valid hex: {value!r}")
    return value.lower()


def _validate_txid(txid: str) -> str:
    """Validate a 64-char hex txid."""
    _require(isinstance(txid, str) and len(txid) == 64,
             "INVALID_FIXTURE", f"txid must be 64 hex chars, got: {txid!r}")
    _validate_hex(txid, "txid")
    return txid.lower()


def _validate_utxo(u: dict, idx: int) -> dict:
    prefix = f"utxos[{idx}]"
    _require(isinstance(u, dict), "INVALID_FIXTURE", f"{prefix} must be an object")

    txid = _validate_txid(u.get("txid", ""))
    vout = u.get("vout")
    _require(isinstance(vout, int) and vout >= 0,
             "INVALID_FIXTURE", f"{prefix}.vout must be a non-negative integer")

    value = u.get("value_sats")
    _require(isinstance(value, int) and value > 0,
             "INVALID_FIXTURE", f"{prefix}.value_sats must be a positive integer")

    spk = _validate_hex(u.get("script_pubkey_hex", ""), f"{prefix}.script_pubkey_hex")
    _require(len(spk) >= 2, "INVALID_FIXTURE", f"{prefix}.script_pubkey_hex too short")

    script_type = u.get("script_type", "")
    _require(script_type in VALID_SCRIPT_TYPES,
             "INVALID_FIXTURE",
             f"{prefix}.script_type '{script_type}' not in {VALID_SCRIPT_TYPES}")

    return {
        "txid": txid,
        "vout": vout,
        "value_sats": value,
        "script_pubkey_hex": spk,
        "script_type": script_type,
        "address": u.get("address", ""),
    }


def _validate_payment(p: dict, idx: int) -> dict:
    prefix = f"payments[{idx}]"
    _require(isinstance(p, dict), "INVALID_FIXTURE", f"{prefix} must be an object")

    value = p.get("value_sats")
    _require(isinstance(value, int) and value > 0,
             "INVALID_FIXTURE", f"{prefix}.value_sats must be a positive integer")

    spk = _validate_hex(p.get("script_pubkey_hex", ""), f"{prefix}.script_pubkey_hex")
    _require(len(spk) >= 2, "INVALID_FIXTURE", f"{prefix}.script_pubkey_hex too short")

    script_type = p.get("script_type", "")
    _require(script_type in VALID_SCRIPT_TYPES,
             "INVALID_FIXTURE",
             f"{prefix}.script_type '{script_type}' not in {VALID_SCRIPT_TYPES}")

    return {
        "address": p.get("address", ""),
        "script_pubkey_hex": spk,
        "script_type": script_type,
        "value_sats": value,
    }


def _validate_change(c: dict) -> dict:
    _require(isinstance(c, dict), "INVALID_FIXTURE", "change must be an object")
    spk = _validate_hex(c.get("script_pubkey_hex", ""), "change.script_pubkey_hex")
    _require(len(spk) >= 2, "INVALID_FIXTURE", "change.script_pubkey_hex too short")

    script_type = c.get("script_type", "")
    _require(script_type in VALID_SCRIPT_TYPES,
             "INVALID_FIXTURE",
             f"change.script_type '{script_type}' not in {VALID_SCRIPT_TYPES}")

    return {
        "address": c.get("address", ""),
        "script_pubkey_hex": spk,
        "script_type": script_type,
    }


def validate_fixture(raw: dict) -> dict:
    """
    Parse and validate a raw fixture dict.
    Returns a clean, normalized fixture dict or raises FixtureError.
    """
    _require(isinstance(raw, dict), "INVALID_FIXTURE", "Fixture must be a JSON object")

    # Network
    network = raw.get("network", "mainnet")
    _require(network in VALID_NETWORKS,
             "INVALID_FIXTURE", f"network '{network}' must be one of {VALID_NETWORKS}")

    # UTXOs
    utxos_raw = raw.get("utxos")
    _require(isinstance(utxos_raw, list) and len(utxos_raw) > 0,
             "INVALID_FIXTURE", "utxos must be a non-empty array")
    utxos = [_validate_utxo(u, i) for i, u in enumerate(utxos_raw)]

    # Check for duplicate UTXOs (same txid+vout)
    seen = set()
    for u in utxos:
        key = (u["txid"], u["vout"])
        _require(key not in seen, "INVALID_FIXTURE",
                 f"Duplicate UTXO: {u['txid']}:{u['vout']}")
        seen.add(key)

    # Payments
    payments_raw = raw.get("payments")
    _require(isinstance(payments_raw, list) and len(payments_raw) > 0,
             "INVALID_FIXTURE", "payments must be a non-empty array")
    payments = [_validate_payment(p, i) for i, p in enumerate(payments_raw)]

    total_payment = sum(p["value_sats"] for p in payments)
    total_utxo = sum(u["value_sats"] for u in utxos)
    _require(total_payment > 0, "INVALID_FIXTURE", "Total payment must be > 0")
    _require(total_utxo >= total_payment,
             "INSUFFICIENT_FUNDS",
             f"UTXOs total {total_utxo} sats < payment total {total_payment} sats (before fees)")

    # Change
    change_raw = raw.get("change")
    _require(change_raw is not None, "INVALID_FIXTURE", "change template is required")
    change = _validate_change(change_raw)

    # Fee rate
    fee_rate = raw.get("fee_rate_sat_vb")
    _require(fee_rate is not None, "INVALID_FIXTURE", "fee_rate_sat_vb is required")
    _require(isinstance(fee_rate, (int, float)) and fee_rate > 0,
             "INVALID_FIXTURE", "fee_rate_sat_vb must be a positive number")
    fee_rate = float(fee_rate)

    # Optional fields
    rbf = raw.get("rbf", False)
    _require(isinstance(rbf, bool), "INVALID_FIXTURE", "rbf must be a boolean")

    locktime_field = raw.get("locktime")
    if locktime_field is not None:
        _require(isinstance(locktime_field, int) and 0 <= locktime_field <= 0xFFFFFFFF,
                 "INVALID_FIXTURE", "locktime must be a uint32")

    current_height = raw.get("current_height")
    if current_height is not None:
        _require(isinstance(current_height, int) and current_height >= 0,
                 "INVALID_FIXTURE", "current_height must be a non-negative integer")

    # Policy
    policy_raw = raw.get("policy", {})
    _require(isinstance(policy_raw, dict), "INVALID_FIXTURE", "policy must be an object")
    max_inputs = policy_raw.get("max_inputs")
    if max_inputs is not None:
        _require(isinstance(max_inputs, int) and max_inputs > 0,
                 "INVALID_FIXTURE", "policy.max_inputs must be a positive integer")

    return {
        "network": network,
        "utxos": utxos,
        "payments": payments,
        "change": change,
        "fee_rate_sat_vb": fee_rate,
        "rbf": rbf,
        "locktime_field": locktime_field,
        "current_height": current_height,
        "policy": {
            "max_inputs": max_inputs,
        },
    }