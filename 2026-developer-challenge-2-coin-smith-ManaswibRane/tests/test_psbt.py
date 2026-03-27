"""
tests/test_psbt.py
Unit tests for PSBT (BIP-174) construction.
"""
import base64
import struct
# import pytest (unavailable in this env)
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests.conftest_compat  # noqa: F401 — installs pytest shim if needed

from app.psbt import build_psbt, decode_psbt_summary, varint, le32, le64


# ── helpers ───────────────────────────────────────────────────────────────────

def _input(value=100_000, script_type="p2wpkh"):
    return {
        "txid":             "ab" * 32,
        "vout":             0,
        "value_sats":       value,
        "script_pubkey_hex":"0014751e76e8199196f454f032d4f736e6a52222bdf5",
        "script_type":      script_type,
    }

def _output(value=70_000):
    return {"value_sats": value, "script_pubkey_hex": "0014751e76e8199196f454f032d4f736e6a52222bdf5"}


# ── varint helper ─────────────────────────────────────────────────────────────

class TestVarint:
    def test_small_value_single_byte(self):
        assert varint(0)   == b"\x00"
        assert varint(1)   == b"\x01"
        assert varint(252) == b"\xfc"

    def test_two_byte_fd_prefix(self):
        enc = varint(253)
        assert enc[0:1] == b"\xfd"
        assert len(enc) == 3

    def test_four_byte_fe_prefix(self):
        enc = varint(0x10000)
        assert enc[0:1] == b"\xfe"
        assert len(enc) == 5


# ── build_psbt ────────────────────────────────────────────────────────────────

class TestBuildPsbt:
    def test_returns_non_empty_string(self):
        b64 = build_psbt([_input()], [_output()], 0, 0xFFFFFFFF)
        assert isinstance(b64, str) and len(b64) > 0

    def test_base64_decodes_successfully(self):
        b64 = build_psbt([_input()], [_output()], 0, 0xFFFFFFFF)
        raw = base64.b64decode(b64)
        assert len(raw) > 0

    def test_psbt_magic_bytes(self):
        """PSBT must start with magic 'psbt\\xff' (5 bytes)."""
        b64 = build_psbt([_input()], [_output()], 0, 0xFFFFFFFF)
        raw = base64.b64decode(b64)
        assert raw[:5] == b"psbt\xff", f"Got: {raw[:5]}"

    def test_decode_summary_valid(self):
        b64 = build_psbt([_input()], [_output()], 0, 0xFFFFFFFF)
        summary = decode_psbt_summary(b64)
        assert summary["valid"] is True

    def test_decode_summary_invalid_rejects(self):
        summary = decode_psbt_summary(base64.b64encode(b"not a psbt").decode())
        assert summary["valid"] is False

    def test_locktime_encoded_in_psbt(self):
        """nLockTime 850000 must appear in the raw transaction bytes."""
        b64 = build_psbt([_input()], [_output()], n_lock_time=850_000, n_sequence=0xFFFFFFFD)
        raw = base64.b64decode(b64)
        # 850000 in LE = 0x000CF850
        assert b"\x50\xf8\x0c\x00" in raw

    def test_sequence_encoded_in_psbt(self):
        """nSequence 0xFFFFFFFD must appear in the unsigned tx."""
        b64 = build_psbt([_input()], [_output()], n_lock_time=0, n_sequence=0xFFFFFFFD)
        raw = base64.b64decode(b64)
        assert b"\xfd\xff\xff\xff" in raw

    def test_p2wpkh_uses_witness_utxo_key(self):
        """SegWit inputs should use PSBT key 0x04 (witness_utxo)."""
        b64 = build_psbt([_input(script_type="p2wpkh")], [_output()], 0, 0xFFFFFFFF)
        raw = base64.b64decode(b64)
        # key 0x04 encoded as \x01\x04 (length 1, byte 0x04)
        assert b"\x01\x04" in raw

    def test_p2pkh_uses_non_witness_utxo_key(self):
        """Legacy inputs should use PSBT key 0x01 (non_witness_utxo)."""
        inp = _input(script_type="p2pkh")
        inp["script_pubkey_hex"] = "76a914751e76e8199196f454f032d4f736e6a52222bdf588ac"
        b64 = build_psbt([inp], [_output()], 0, 0xFFFFFFFF)
        raw = base64.b64decode(b64)
        assert b"\x01\x01" in raw

    def test_multiple_inputs_longer_psbt(self):
        """Two inputs should produce a longer PSBT than one."""
        one = len(base64.b64decode(build_psbt([_input()], [_output()], 0, 0xFFFFFFFF)))
        two = len(base64.b64decode(build_psbt([_input(), _input()], [_output()], 0, 0xFFFFFFFF)))
        assert two > one