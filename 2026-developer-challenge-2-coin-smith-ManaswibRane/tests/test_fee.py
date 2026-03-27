"""
tests/test_fee.py
Unit tests for fee estimation and fee+change computation logic.
"""
import math
# import pytest (unavailable in this env)
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests.conftest_compat  # noqa: F401 — installs pytest shim if needed

from app.fee import (
    estimate_vbytes,
    estimate_tx_weight,
    compute_fee_and_change,
    required_fee,
    DUST_THRESHOLD,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def utxo(value=100_000, script_type="p2wpkh", n=0):
    return {
        "txid":             "a" * 64,
        "vout":             n,
        "value_sats":       value,
        "script_pubkey_hex":"0014751e76e8199196f454f032d4f736e6a52222bdf5",
        "script_type":      script_type,
    }


def payment(value=70_000, script_type="p2wpkh"):
    return {
        "value_sats":       value,
        "script_pubkey_hex":"0014751e76e8199196f454f032d4f736e6a52222bdf5",
        "script_type":      script_type,
    }


def change_tmpl(script_type="p2wpkh"):
    return {
        "address":          "bc1q...",
        "script_pubkey_hex":"0014751e76e8199196f454f032d4f736e6a52222bdf5",
        "script_type":      script_type,
    }


# ── vbytes / weight ───────────────────────────────────────────────────────────

class TestVbytes:
    def test_single_p2wpkh_1in_2out_near_141(self):
        """1 P2WPKH in + 2 P2WPKH out ≈ 141 vbytes (industry standard benchmark)."""
        vb = estimate_vbytes([utxo()], [payment(70_000), payment(20_000)])
        assert 130 <= vb <= 160, f"Expected ~141, got {vb}"

    def test_vbytes_increases_with_inputs(self):
        """Adding an input must increase vbytes."""
        one = estimate_vbytes([utxo()], [payment()])
        two = estimate_vbytes([utxo(), utxo(n=1)], [payment()])
        assert two > one

    def test_vbytes_increases_with_outputs(self):
        """Adding an output must increase vbytes."""
        one = estimate_vbytes([utxo()], [payment()])
        two = estimate_vbytes([utxo()], [payment(), payment()])
        assert two > one

    def test_p2pkh_larger_than_p2wpkh(self):
        """Legacy P2PKH inputs are heavier than SegWit P2WPKH inputs."""
        segwit = estimate_vbytes([utxo(script_type="p2wpkh")], [payment()])
        legacy = estimate_vbytes([utxo(script_type="p2pkh")],  [payment()])
        assert legacy > segwit

    def test_weight_divisible_by_vbytes_ceil(self):
        """vbytes == ceil(weight / 4)."""
        inputs  = [utxo()]
        outputs = [payment()]
        weight = estimate_tx_weight(inputs, outputs)
        assert estimate_vbytes(inputs, outputs) == math.ceil(weight / 4)

    def test_required_fee_ceiled(self):
        """required_fee must be an integer >= vbytes * fee_rate."""
        inputs  = [utxo()]
        outputs = [payment()]
        vb   = estimate_vbytes(inputs, outputs)
        fee  = required_fee(inputs, outputs, fee_rate_sat_vb=5.0)
        assert isinstance(fee, int)
        assert fee >= vb * 5.0


# ── compute_fee_and_change ────────────────────────────────────────────────────

class TestFeeAndChange:
    def test_change_created_when_ample_leftover(self):
        """100k input, 70k payment → change should be created."""
        fee, chg, vb = compute_fee_and_change(
            [utxo(100_000)], [payment(70_000)], change_tmpl(), 5.0
        )
        assert chg is not None
        assert chg >= DUST_THRESHOLD

    def test_balance_equation_holds(self):
        """sum(inputs) == sum(payments) + change + fee (strict)."""
        fee, chg, vb = compute_fee_and_change(
            [utxo(100_000)], [payment(70_000)], change_tmpl(), 5.0
        )
        assert 100_000 == 70_000 + (chg or 0) + fee

    def test_send_all_when_tiny_leftover(self):
        """71k input, 70k payment at 5 sat/vb → change is dust → SEND_ALL."""
        fee, chg, vb = compute_fee_and_change(
            [utxo(71_000)], [payment(70_000)], change_tmpl(), 5.0
        )
        assert chg is None, f"Expected no change (SEND_ALL), got {chg}"

    def test_send_all_fee_absorbs_all_leftover(self):
        """In SEND_ALL mode fee == total_in - total_payments."""
        fee, chg, vb = compute_fee_and_change(
            [utxo(71_000)], [payment(70_000)], change_tmpl(), 5.0
        )
        assert chg is None
        assert fee == 71_000 - 70_000

    def test_change_never_below_dust(self):
        """When change is created it must be >= DUST_THRESHOLD."""
        fee, chg, vb = compute_fee_and_change(
            [utxo(100_000)], [payment(70_000)], change_tmpl(), 5.0
        )
        if chg is not None:
            assert chg >= DUST_THRESHOLD

    def test_fee_meets_target_rate(self):
        """Actual fee / vbytes >= fee_rate (never underpay)."""
        rate = 10.0
        fee, chg, vb = compute_fee_and_change(
            [utxo(100_000)], [payment(60_000)], change_tmpl(), rate
        )
        assert fee / vb >= rate - 0.01  # tiny float tolerance