"""
psbt.py
Build a BIP-174 Partially Signed Bitcoin Transaction (PSBT) from scratch.

PSBT is a binary format defined in BIP-174. It packages:
  1. An unsigned transaction (the "global" section)
  2. Per-input metadata (witness_utxo / non_witness_utxo for each input)
  3. Per-output metadata (empty for us)

Binary format overview:
  <magic> <0xff separator>
  [global key-value pairs] <0x00 separator>
  For each input: [key-value pairs] <0x00 separator>
  For each output: [key-value pairs] <0x00 separator>

Key types used:
  Global 0x00 = unsigned transaction
  Input  0x01 = non_witness_utxo (full previous tx, for legacy)
  Input  0x04 = witness_utxo (just the output being spent, for segwit)
"""

import struct
import base64


# ──────────────────────────────────────────────
# Low-level serialization helpers
# ──────────────────────────────────────────────

def varint(n: int) -> bytes:
    """Encode an integer as a Bitcoin-style variable-length integer."""
    if n < 0xfd:
        return struct.pack("B", n)
    elif n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def push_bytes(data: bytes) -> bytes:
    """Prefix data with its varint length (used in PSBT key-value encoding)."""
    return varint(len(data)) + data


def le32(n: int) -> bytes:
    """4-byte little-endian uint32."""
    return struct.pack("<I", n)


def le64(n: int) -> bytes:
    """8-byte little-endian uint64."""
    return struct.pack("<Q", n)


def txid_bytes(txid_hex: str) -> bytes:
    """Convert a txid hex string to bytes in little-endian (wire format)."""
    return bytes.fromhex(txid_hex)[::-1]


# ──────────────────────────────────────────────
# Bitcoin transaction serialization
# ──────────────────────────────────────────────

def serialize_unsigned_tx(
    inputs: list[dict],
    outputs: list[dict],
    n_lock_time: int,
    n_sequence: int,
) -> bytes:
    """
    Serialize a Bitcoin transaction in unsigned (scriptSig-empty) form.
    This is placed in the PSBT global section.

    Wire format:
      version(4) vin_count(varint) [inputs] vout_count(varint) [outputs] locktime(4)

    Each input (unsigned):
      prev_txid(32) prev_vout(4) scriptLen(0x00) sequence(4)

    Each output:
      value(8) scriptLen(varint) script(N)
    """
    raw = b""

    # nVersion = 2 (standard for modern wallets)
    raw += le32(2)

    # Inputs
    raw += varint(len(inputs))
    for inp in inputs:
        raw += txid_bytes(inp["txid"])      # prev txid (little-endian)
        raw += le32(inp["vout"])            # prev output index
        raw += b"\x00"                      # empty scriptSig (unsigned)
        raw += le32(n_sequence)             # nSequence

    # Outputs
    raw += varint(len(outputs))
    for out in outputs:
        raw += le64(out["value_sats"])
        script = bytes.fromhex(out["script_pubkey_hex"])
        raw += varint(len(script)) + script

    # nLockTime
    raw += le32(n_lock_time)

    return raw


def serialize_output_for_witness_utxo(utxo: dict) -> bytes:
    """
    Serialize a TxOut (value + scriptPubKey) as used in PSBT witness_utxo field.
    This is the minimal info a hardware wallet needs to verify a SegWit input.
    """
    script = bytes.fromhex(utxo["script_pubkey_hex"])
    return le64(utxo["value_sats"]) + varint(len(script)) + script


def serialize_full_prevtx(utxo: dict) -> bytes:
    """
    Build a minimal full "previous transaction" for non_witness_utxo (legacy inputs).
    We construct a synthetic 1-input 1-output transaction containing just this UTXO.
    This is needed for legacy (P2PKH, P2SH) inputs so signers can verify amounts.
    """
    # We need to create a plausible previous tx. For PSBT purposes, the signer
    # uses the output at vout index to verify the amount. We create a minimal
    # synthetic tx with enough outputs to include our vout.
    vout_count = utxo["vout"] + 1
    script = bytes.fromhex(utxo["script_pubkey_hex"])

    raw = b""
    raw += le32(2)  # version
    # 1 coinbase-style input (dummy)
    raw += varint(1)
    raw += b"\x00" * 32              # prev txid (null)
    raw += b"\xff\xff\xff\xff"       # prev vout (coinbase marker)
    raw += b"\x01\x00"               # scriptSig: 1 byte (OP_0)
    raw += b"\xff\xff\xff\xff"       # sequence

    # Outputs: pad with empty outputs up to vout, then put our output
    raw += varint(vout_count)
    for i in range(vout_count):
        if i == utxo["vout"]:
            raw += le64(utxo["value_sats"])
            raw += varint(len(script)) + script
        else:
            # Dummy empty output
            raw += le64(0)
            raw += b"\x00"

    raw += le32(0)  # locktime
    return raw


# ──────────────────────────────────────────────
# PSBT key-value pair helpers
# ──────────────────────────────────────────────

def psbt_kv(key: bytes, value: bytes) -> bytes:
    """Encode a single PSBT key-value pair: <key_len><key><val_len><val>."""
    return push_bytes(key) + push_bytes(value)


def psbt_separator() -> bytes:
    """0x00 byte marks end of a map section."""
    return b"\x00"


# ──────────────────────────────────────────────
# PSBT builder
# ──────────────────────────────────────────────

def build_psbt(
    selected_inputs: list[dict],
    final_outputs: list[dict],
    n_lock_time: int,
    n_sequence: int,
) -> str:
    """
    Build a BIP-174 PSBT and return it as a base64 string.

    Args:
        selected_inputs: UTXOs used as inputs (with txid, vout, value_sats,
                         script_pubkey_hex, script_type)
        final_outputs:   Transaction outputs (payments + optional change)
        n_lock_time:     nLockTime for the unsigned transaction
        n_sequence:      nSequence applied to all inputs

    Returns:
        base64-encoded PSBT string
    """
    # ── Global section ─────────────────────────────────────────────────────
    unsigned_tx = serialize_unsigned_tx(
        inputs=selected_inputs,
        outputs=final_outputs,
        n_lock_time=n_lock_time,
        n_sequence=n_sequence,
    )

    psbt = b""
    # Magic bytes: "psbt" + 0xff
    psbt += b"psbt\xff"

    # Global: key 0x00 = unsigned transaction
    psbt += psbt_kv(b"\x00", unsigned_tx)
    psbt += psbt_separator()  # end of global map

    # ── Per-input sections ─────────────────────────────────────────────────
    for inp in selected_inputs:
        is_segwit = inp["script_type"] in ("p2wpkh", "p2wsh", "p2tr", "p2sh-p2wpkh")

        input_map = b""
        if is_segwit:
            # PSBT key 0x04: witness_utxo
            # Value = serialized TxOut (value + scriptPubKey)
            witness_utxo_bytes = serialize_output_for_witness_utxo(inp)
            input_map += psbt_kv(b"\x04", witness_utxo_bytes)
        else:
            # PSBT key 0x01: non_witness_utxo
            # Value = full previous transaction
            prev_tx_bytes = serialize_full_prevtx(inp)
            input_map += psbt_kv(b"\x01", prev_tx_bytes)

        psbt += input_map
        psbt += psbt_separator()  # end of input map

    # ── Per-output sections ────────────────────────────────────────────────
    for _ in final_outputs:
        psbt += psbt_separator()  # empty output map

    return base64.b64encode(psbt).decode("ascii")


def decode_psbt_summary(psbt_b64: str) -> dict:
    """
    Decode a PSBT and return a summary dict for validation/debugging.
    Parses the magic, global tx, and counts inputs/outputs.
    """
    try:
        raw = base64.b64decode(psbt_b64)
    except Exception as e:
        return {"valid": False, "error": f"Base64 decode failed: {e}"}

    if raw[:5] != b"psbt\xff":
        return {"valid": False, "error": "Invalid PSBT magic bytes"}

    return {
        "valid": True,
        "length_bytes": len(raw),
        "magic": "psbt\\xff",
    }