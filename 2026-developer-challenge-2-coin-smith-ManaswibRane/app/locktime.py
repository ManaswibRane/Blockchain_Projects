"""
locktime.py
RBF signaling and locktime construction per BIP-125 and Bitcoin Core behavior.

Key concepts:
  nSequence: A per-input field that controls Replace-By-Fee (RBF) signaling
             and whether locktime is enforced.
  nLockTime: A transaction-level field that prevents a tx from being mined
             until a certain block height or Unix timestamp.
"""


def compute_sequence_and_locktime(
    rbf: bool,
    locktime_field: int | None,
    current_height: int | None,
) -> tuple[int, int, str]:
    """
    Compute nSequence (per-input) and nLockTime (per-transaction) per the spec.

    Rules from the interaction matrix:
    ┌──────────┬──────────────────┬───────────────┬────────────┬────────────────────────┐
    │ rbf      │ locktime present │ current_height│ nSequence  │ nLockTime              │
    ├──────────┼──────────────────┼───────────────┼────────────┼────────────────────────┤
    │ false    │ no               │ —             │ 0xFFFFFFFF │ 0                      │
    │ false    │ yes              │ —             │ 0xFFFFFFFE │ locktime               │
    │ true     │ no               │ yes           │ 0xFFFFFFFD │ current_height (snipe) │
    │ true     │ yes              │ —             │ 0xFFFFFFFD │ locktime               │
    │ true     │ no               │ no            │ 0xFFFFFFFD │ 0                      │
    └──────────┴──────────────────┴───────────────┴────────────┴────────────────────────┘

    Anti-fee-sniping: When rbf=true and current_height is provided but no explicit
    locktime, we set nLockTime = current_height. This is Bitcoin Core's default behavior
    to prevent miners from "sniping" fees from recent blocks.

    Args:
        rbf: Whether to signal Replace-By-Fee (BIP-125)
        locktime_field: Explicit locktime from fixture (None if not specified)
        current_height: Current chain tip block height (None if not specified)

    Returns:
        (nSequence, nLockTime, locktime_type)
        where locktime_type is "none", "block_height", or "unix_timestamp"
    """

    # ── Step 1: Determine nLockTime ──────────────────────────────────────────
    if locktime_field is not None:
        # Explicit locktime always wins
        n_lock_time = locktime_field
    elif rbf and current_height is not None:
        # Anti-fee-sniping: use current block height as locktime
        n_lock_time = current_height
    else:
        n_lock_time = 0

    # ── Step 2: Determine nSequence ──────────────────────────────────────────
    if rbf:
        # BIP-125 RBF opt-in: any input with nSequence <= 0xFFFFFFFD
        n_sequence = 0xFFFFFFFD
    elif n_lock_time != 0:
        # Enable locktime without RBF: nSequence must be < 0xFFFFFFFF
        n_sequence = 0xFFFFFFFE
    else:
        # Final: no RBF, no locktime
        n_sequence = 0xFFFFFFFF

    # ── Step 3: Classify locktime ─────────────────────────────────────────────
    # Bitcoin uses 500_000_000 as the boundary:
    # values below it are block heights, values at/above are Unix timestamps
    if n_lock_time == 0:
        locktime_type = "none"
    elif n_lock_time < 500_000_000:
        locktime_type = "block_height"
    else:
        locktime_type = "unix_timestamp"

    return n_sequence, n_lock_time, locktime_type