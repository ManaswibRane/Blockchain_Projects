"""
tests/test_coin_select.py
Unit tests for coin selection strategies.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.coin_select import (
    greedy_select,
    consolidate_select,
    select_coins,
    InsufficientFundsError,
    PolicyViolationError,
)


def _utxo(value, idx=0):
    return {
        "txid":             chr(ord('a') + idx) * 64,
        "vout":             idx,
        "value_sats":       value,
        "script_pubkey_hex":"0014751e76e8199196f454f032d4f736e6a52222bdf5",
        "script_type":      "p2wpkh",
        "address":          "bc1q...",
    }

def _payment(value):
    return {"value_sats": value, "script_pubkey_hex": "0014751e76e8199196f454f032d4f736e6a52222bdf5",
            "script_type": "p2wpkh", "address": "bc1q..."}

def _change():
    return {"address": "bc1q...", "script_pubkey_hex": "0014751e76e8199196f454f032d4f736e6a52222bdf5",
            "script_type": "p2wpkh"}


class TestGreedy:
    def test_picks_largest_first(self):
        utxos = [_utxo(10_000, 0), _utxo(50_000, 1), _utxo(5_000, 2)]
        sel = greedy_select(utxos, [_payment(30_000)], _change(), 5.0)
        assert sel[0]["value_sats"] == 50_000

    def test_stops_as_soon_as_enough(self):
        utxos = [_utxo(100_000, 0), _utxo(50_000, 1)]
        sel = greedy_select(utxos, [_payment(60_000)], _change(), 5.0)
        assert len(sel) == 1

    def test_uses_multiple_when_needed(self):
        utxos = [_utxo(30_000, 0), _utxo(30_000, 1)]
        sel = greedy_select(utxos, [_payment(50_000)], _change(), 5.0)
        assert len(sel) == 2

    def test_raises_on_insufficient_funds(self):
        raised = False
        try:
            greedy_select([_utxo(1_000, 0)], [_payment(50_000)], _change(), 5.0)
        except InsufficientFundsError:
            raised = True
        assert raised, "Expected InsufficientFundsError"

    def test_max_inputs_respected(self):
        utxos = [_utxo(20_000, i) for i in range(5)]
        sel = greedy_select(utxos, [_payment(10_000)], _change(), 5.0, max_inputs=2)
        assert len(sel) <= 2

    def test_max_inputs_policy_violation(self):
        utxos = [_utxo(10_000, i) for i in range(5)]
        raised = False
        try:
            greedy_select(utxos, [_payment(45_000)], _change(), 5.0, max_inputs=2)
        except PolicyViolationError:
            raised = True
        assert raised, "Expected PolicyViolationError"


class TestConsolidate:
    def test_picks_smallest_first(self):
        utxos = [_utxo(50_000, 0), _utxo(5_000, 1), _utxo(10_000, 2)]
        sel = consolidate_select(utxos, [_payment(4_000)], _change(), 1.0)
        assert sel[0]["value_sats"] == 5_000

    def test_raises_on_insufficient_funds(self):
        raised = False
        try:
            consolidate_select([_utxo(500, 0)], [_payment(50_000)], _change(), 5.0)
        except InsufficientFundsError:
            raised = True
        assert raised, "Expected InsufficientFundsError"


class TestDispatcher:
    def test_greedy_strategy_keyword(self):
        utxos = [_utxo(100_000, 0)]
        sel, name = select_coins(utxos, [_payment(50_000)], _change(), 5.0, strategy="greedy")
        assert name == "greedy"
        assert len(sel) >= 1

    def test_consolidate_strategy_keyword(self):
        utxos = [_utxo(100_000, 0), _utxo(10_000, 1)]
        sel, name = select_coins(utxos, [_payment(8_000)], _change(), 1.0, strategy="consolidate")
        assert name == "consolidate"

    def test_unknown_strategy_falls_back_to_greedy(self):
        utxos = [_utxo(100_000, 0)]
        sel, name = select_coins(utxos, [_payment(50_000)], _change(), 5.0, strategy="banana")
        assert len(sel) >= 1