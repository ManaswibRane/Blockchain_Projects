"""
tests/test_locktime.py
Unit tests for RBF signaling + locktime logic (BIP-125 interaction matrix).
"""
# import pytest (unavailable in this env)
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests.conftest_compat  # noqa: F401 — installs pytest shim if needed

from app.locktime import compute_sequence_and_locktime


class TestSequenceLocktime:
    # ── nSequence values ──────────────────────────────────────────────────────

    def test_rbf_true_sequence_is_ffd(self):
        seq, _, _ = compute_sequence_and_locktime(True, None, None)
        assert seq == 0xFFFFFFFD

    def test_no_rbf_no_locktime_sequence_is_ffff(self):
        seq, lt, lt_type = compute_sequence_and_locktime(False, None, None)
        assert seq  == 0xFFFFFFFF
        assert lt   == 0
        assert lt_type == "none"

    def test_locktime_without_rbf_sequence_is_fffe(self):
        seq, lt, _ = compute_sequence_and_locktime(False, 850_000, None)
        assert seq == 0xFFFFFFFE
        assert lt  == 850_000

    def test_rbf_with_explicit_locktime_sequence_is_ffd(self):
        seq, lt, _ = compute_sequence_and_locktime(True, 850_000, None)
        assert seq == 0xFFFFFFFD
        assert lt  == 850_000

    # ── nLockTime values ──────────────────────────────────────────────────────

    def test_anti_fee_sniping_sets_locktime_to_height(self):
        """rbf=True + current_height + no explicit locktime → nLockTime = current_height."""
        _, lt, _ = compute_sequence_and_locktime(True, None, 850_000)
        assert lt == 850_000

    def test_explicit_locktime_overrides_height(self):
        """Explicit locktime always wins over current_height."""
        _, lt, _ = compute_sequence_and_locktime(True, 999_999, 850_000)
        assert lt == 999_999

    def test_no_rbf_no_locktime_no_height_locktime_zero(self):
        _, lt, _ = compute_sequence_and_locktime(False, None, None)
        assert lt == 0

    def test_rbf_true_no_locktime_no_height_locktime_zero(self):
        _, lt, _ = compute_sequence_and_locktime(True, None, None)
        assert lt == 0

    # ── locktime_type classification ──────────────────────────────────────────

    def test_zero_locktime_is_none(self):
        _, _, lt_type = compute_sequence_and_locktime(False, None, None)
        assert lt_type == "none"

    def test_locktime_1_is_block_height(self):
        _, _, lt_type = compute_sequence_and_locktime(False, 1, None)
        assert lt_type == "block_height"

    def test_locktime_499999999_is_block_height(self):
        """Boundary: 499_999_999 is still block_height."""
        _, lt, lt_type = compute_sequence_and_locktime(True, 499_999_999, None)
        assert lt_type  == "block_height"
        assert lt       == 499_999_999

    def test_locktime_500000000_is_unix_timestamp(self):
        """Boundary: 500_000_000 is the first unix_timestamp."""
        _, lt, lt_type = compute_sequence_and_locktime(True, 500_000_000, None)
        assert lt_type  == "unix_timestamp"
        assert lt       == 500_000_000

    def test_locktime_1700000000_is_unix_timestamp(self):
        _, _, lt_type = compute_sequence_and_locktime(False, 1_700_000_000, None)
        assert lt_type == "unix_timestamp"