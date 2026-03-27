"""
tests/test_builder.py
End-to-end integration tests for the core PSBT builder.
"""
import base64
# import pytest (unavailable in this env)
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests.conftest_compat  # noqa: F401 — installs pytest shim if needed

from app.builder import build_transaction


# ── helpers ───────────────────────────────────────────────────────────────────

def _utxo(value, idx=0, script_type="p2wpkh"):
    return {
        "txid":             chr(ord('a') + idx) * 64,
        "vout":             idx,
        "value_sats":       value,
        "script_pubkey_hex":"0014751e76e8199196f454f032d4f736e6a52222bdf5",
        "script_type":      script_type,
        "address":          "bc1q...",
    }

def _payment(value, script_type="p2wpkh"):
    return {"address": "bc1q...", "script_pubkey_hex": "0014751e76e8199196f454f032d4f736e6a52222bdf5",
            "script_type": script_type, "value_sats": value}

def _change(script_type="p2wpkh"):
    return {"address": "bc1q...", "script_pubkey_hex": "0014751e76e8199196f454f032d4f736e6a52222bdf5",
            "script_type": script_type}

def _fixture(utxo_vals, payment_vals, fee_rate=5, rbf=False,
             locktime=None, current_height=None, max_inputs=None,
             script_type="p2wpkh"):
    f = {
        "network":         "mainnet",
        "utxos":           [_utxo(v, i, script_type) for i, v in enumerate(utxo_vals)],
        "payments":        [_payment(v, script_type) for v in payment_vals],
        "change":          _change(script_type),
        "fee_rate_sat_vb": fee_rate,
        "rbf":             rbf,
    }
    if locktime is not None:        f["locktime"]        = locktime
    if current_height is not None:  f["current_height"]  = current_height
    if max_inputs is not None:      f["policy"] = {"max_inputs": max_inputs}
    return f


# ── success cases ─────────────────────────────────────────────────────────────

class TestBuilderSuccess:
    def test_ok_true_for_valid_fixture(self):
        r = build_transaction(_fixture([100_000], [70_000]))
        assert r["ok"] is True

    def test_balance_equation_holds(self):
        r = build_transaction(_fixture([100_000], [70_000]))
        assert r["ok"]
        total_in  = sum(i["value_sats"] for i in r["selected_inputs"])
        total_out = sum(o["value_sats"] for o in r["outputs"])
        assert total_in == total_out + r["fee_sats"]

    def test_psbt_base64_present_and_valid(self):
        r = build_transaction(_fixture([100_000], [70_000]))
        assert r["ok"]
        raw = base64.b64decode(r["psbt_base64"])
        assert raw[:5] == b"psbt\xff"

    def test_change_output_present(self):
        r = build_transaction(_fixture([100_000], [70_000], fee_rate=5))
        assert r["ok"]
        assert r["change_index"] is not None
        assert r["outputs"][r["change_index"]]["is_change"] is True

    def test_change_index_null_on_send_all(self):
        # 71k input, 70k payment → dust change → SEND_ALL
        r = build_transaction(_fixture([71_000], [70_000], fee_rate=5))
        assert r["ok"]
        assert r["change_index"] is None

    def test_send_all_warning_emitted(self):
        r = build_transaction(_fixture([71_000], [70_000], fee_rate=5))
        assert r["ok"]
        if r["change_index"] is None:
            codes = [w["code"] for w in r["warnings"]]
            assert "SEND_ALL" in codes

    def test_fee_rate_consistent_with_fee_and_vbytes(self):
        r = build_transaction(_fixture([100_000], [70_000], fee_rate=5))
        assert r["ok"]
        expected = r["fee_sats"] / r["vbytes"]
        assert abs(r["fee_rate_sat_vb"] - expected) <= 0.5

    def test_rbf_signaling_true_when_rbf_set(self):
        r = build_transaction(_fixture([100_000], [70_000], rbf=True))
        assert r["ok"]
        assert r["rbf_signaling"] is True

    def test_rbf_signaling_false_when_not_set(self):
        r = build_transaction(_fixture([100_000], [70_000], rbf=False))
        assert r["ok"]
        assert r["rbf_signaling"] is False

    def test_rbf_warning_emitted(self):
        r = build_transaction(_fixture([100_000], [70_000], rbf=True))
        assert r["ok"]
        codes = [w["code"] for w in r["warnings"]]
        assert "RBF_SIGNALING" in codes

    def test_locktime_in_report(self):
        r = build_transaction(_fixture([100_000], [70_000], locktime=850_000))
        assert r["ok"]
        assert r["locktime"] == 850_000
        assert r["locktime_type"] == "block_height"

    def test_anti_fee_sniping(self):
        r = build_transaction(_fixture([100_000], [70_000], rbf=True, current_height=850_000))
        assert r["ok"]
        assert r["locktime"] == 850_000

    def test_locktime_type_unix_timestamp(self):
        r = build_transaction(_fixture([100_000], [70_000], locktime=1_700_000_000))
        assert r["ok"]
        assert r["locktime_type"] == "unix_timestamp"

    def test_strategy_greedy_in_report(self):
        r = build_transaction(_fixture([100_000], [70_000]), strategy="greedy")
        assert r["ok"]
        assert r["strategy"] == "greedy"

    def test_strategy_consolidate_in_report(self):
        r = build_transaction(_fixture([100_000], [70_000]), strategy="consolidate")
        assert r["ok"]
        assert r["strategy"] == "consolidate"

    def test_multiple_utxos_selected_when_needed(self):
        r = build_transaction(_fixture([30_000, 30_000], [50_000]))
        assert r["ok"]
        assert len(r["selected_inputs"]) == 2

    def test_max_inputs_policy_honoured(self):
        r = build_transaction(_fixture([60_000, 60_000, 60_000], [50_000], max_inputs=2))
        assert r["ok"]
        assert len(r["selected_inputs"]) <= 2

    def test_outputs_include_all_payments(self):
        r = build_transaction(_fixture([200_000], [50_000, 60_000]))
        assert r["ok"]
        payment_outs = [o for o in r["outputs"] if not o["is_change"]]
        assert len(payment_outs) == 2


# ── error cases ───────────────────────────────────────────────────────────────

class TestBuilderErrors:
    def test_ok_false_on_insufficient_funds(self):
        r = build_transaction(_fixture([1_000], [50_000]))
        assert r["ok"] is False
        assert r["error"]["code"] in ("INSUFFICIENT_FUNDS", "INVALID_FIXTURE")

    def test_ok_false_on_invalid_fixture(self):
        r = build_transaction({"not": "a valid fixture"})
        assert r["ok"] is False
        assert "code" in r["error"]
        assert "message" in r["error"]

    def test_ok_false_on_empty_dict(self):
        r = build_transaction({})
        assert r["ok"] is False

    def test_error_has_code_and_message(self):
        r = build_transaction(_fixture([1_000], [50_000]))
        assert r["ok"] is False
        assert isinstance(r["error"]["code"], str)   and r["error"]["code"]
        assert isinstance(r["error"]["message"], str) and r["error"]["message"]