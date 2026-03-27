"""
tests/test_validator.py
Unit tests for defensive fixture parsing.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.validator import validate_fixture, FixtureError


def good_fixture(**overrides):
    base = {
        "network": "mainnet",
        "utxos": [{
            "txid":             "a" * 64,
            "vout":             0,
            "value_sats":       100_000,
            "script_pubkey_hex":"0014751e76e8199196f454f032d4f736e6a52222bdf5",
            "script_type":      "p2wpkh",
            "address":          "bc1q...",
        }],
        "payments": [{
            "address":          "bc1q...",
            "script_pubkey_hex":"0014751e76e8199196f454f032d4f736e6a52222bdf5",
            "script_type":      "p2wpkh",
            "value_sats":       70_000,
        }],
        "change": {
            "address":          "bc1q...",
            "script_pubkey_hex":"0014751e76e8199196f454f032d4f736e6a52222bdf5",
            "script_type":      "p2wpkh",
        },
        "fee_rate_sat_vb": 5,
    }
    base.update(overrides)
    return base


def _raises_fixture_error(fn):
    """Helper: assert fn() raises FixtureError."""
    raised = False
    try:
        fn()
    except FixtureError:
        raised = True
    assert raised, "Expected FixtureError to be raised"


class TestValidFixture:
    def test_accepts_minimal_valid_fixture(self):
        result = validate_fixture(good_fixture())
        assert result["network"] == "mainnet"
        assert len(result["utxos"]) == 1

    def test_normalises_txid_to_lowercase(self):
        f = good_fixture()
        f["utxos"][0]["txid"] = "A" * 64
        result = validate_fixture(f)
        assert result["utxos"][0]["txid"] == "a" * 64

    def test_optional_rbf_defaults_false(self):
        result = validate_fixture(good_fixture())
        assert result["rbf"] is False

    def test_optional_locktime_defaults_none(self):
        result = validate_fixture(good_fixture())
        assert result["locktime_field"] is None

    def test_policy_max_inputs_parsed(self):
        f = good_fixture()
        f["policy"] = {"max_inputs": 3}
        result = validate_fixture(f)
        assert result["policy"]["max_inputs"] == 3


class TestInvalidFixture:
    def test_rejects_non_dict(self):
        _raises_fixture_error(lambda: validate_fixture([1, 2, 3]))

    def test_rejects_empty_utxos(self):
        f = good_fixture(); f["utxos"] = []
        _raises_fixture_error(lambda: validate_fixture(f))

    def test_rejects_short_txid(self):
        f = good_fixture(); f["utxos"][0]["txid"] = "deadbeef"
        _raises_fixture_error(lambda: validate_fixture(f))

    def test_rejects_non_hex_txid(self):
        f = good_fixture(); f["utxos"][0]["txid"] = "Z" * 64
        _raises_fixture_error(lambda: validate_fixture(f))

    def test_rejects_negative_value(self):
        f = good_fixture(); f["utxos"][0]["value_sats"] = -1
        _raises_fixture_error(lambda: validate_fixture(f))

    def test_rejects_zero_value(self):
        f = good_fixture(); f["utxos"][0]["value_sats"] = 0
        _raises_fixture_error(lambda: validate_fixture(f))

    def test_rejects_unknown_script_type(self):
        f = good_fixture(); f["utxos"][0]["script_type"] = "p2banana"
        _raises_fixture_error(lambda: validate_fixture(f))

    def test_rejects_invalid_network(self):
        _raises_fixture_error(lambda: validate_fixture(good_fixture(network="fakechain")))

    def test_rejects_negative_fee_rate(self):
        _raises_fixture_error(lambda: validate_fixture(good_fixture(fee_rate_sat_vb=-1)))

    def test_rejects_zero_fee_rate(self):
        _raises_fixture_error(lambda: validate_fixture(good_fixture(fee_rate_sat_vb=0)))

    def test_rejects_duplicate_utxos(self):
        f = good_fixture()
        f["utxos"].append(f["utxos"][0].copy())
        _raises_fixture_error(lambda: validate_fixture(f))

    def test_rejects_missing_change(self):
        f = good_fixture(); del f["change"]
        _raises_fixture_error(lambda: validate_fixture(f))

    def test_insufficient_funds_detected(self):
        f = good_fixture()
        f["payments"][0]["value_sats"] = 200_000
        raised = False
        try:
            validate_fixture(f)
        except FixtureError as e:
            raised = True
            assert e.code == "INSUFFICIENT_FUNDS"
        assert raised, "Expected INSUFFICIENT_FUNDS FixtureError"