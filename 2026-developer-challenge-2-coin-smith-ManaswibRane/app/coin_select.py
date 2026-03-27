"""
coin_select.py
Coin selection strategies for building Bitcoin transactions.

Coin selection is the process of choosing which UTXOs (unspent transaction outputs)
to use as inputs in a new transaction. The goal is to:
  1. Cover the payment amount + fees
  2. Minimize the number of inputs (smaller tx = lower fee)
  3. Avoid creating tiny "dust" change outputs
  4. Respect policy constraints (max_inputs)
"""

from app.fee import required_fee, compute_fee_and_change, DUST_THRESHOLD


class InsufficientFundsError(Exception):
    """Raised when available UTXOs cannot cover payments + fees."""
    pass


class PolicyViolationError(Exception):
    """Raised when coin selection cannot satisfy policy constraints."""
    pass


# ──────────────────────────────────────────────
# Strategy: Greedy (Largest-First)
# ──────────────────────────────────────────────

def greedy_select(
    utxos: list[dict],
    payments: list[dict],
    change_template: dict,
    fee_rate_sat_vb: float,
    max_inputs: int | None = None,
) -> list[dict]:
    """
    Greedy coin selection: pick largest UTXOs first until we have enough.

    Why largest-first?
    - Fewer inputs needed → smaller transaction → lower fee
    - Consolidates large coins, leaves small ones for future use

    Args:
        utxos: Available UTXOs (the wallet's coin drawer)
        payments: Payment outputs we must fund
        change_template: Change address info (for size estimation)
        fee_rate_sat_vb: Target fee rate in sat/vbyte
        max_inputs: Maximum number of inputs allowed (from policy)

    Returns:
        List of selected UTXOs

    Raises:
        InsufficientFundsError: if we can't cover payments + fees
        PolicyViolationError: if max_inputs prevents covering the amount
    """
    total_payment = sum(p["value_sats"] for p in payments)

    # Sort largest first
    sorted_utxos = sorted(utxos, key=lambda u: u["value_sats"], reverse=True)

    if max_inputs is not None:
        sorted_utxos = sorted_utxos[:max_inputs]

    selected = []
    total_selected = 0

    for utxo in sorted_utxos:
        selected.append(utxo)
        total_selected += utxo["value_sats"]

        # Check with change output (normal case)
        fee_with_change = required_fee(selected, payments + [change_template], fee_rate_sat_vb)
        if total_selected >= total_payment + fee_with_change:
            return selected

        # Check without change output (send-all / near-exact case)
        fee_no_change = required_fee(selected, payments, fee_rate_sat_vb)
        if total_selected >= total_payment + fee_no_change:
            return selected

    # Reached end of available (possibly policy-capped) UTXOs
    if max_inputs is not None and len(utxos) > max_inputs:
        # Check if removing the policy cap would have helped
        all_total = sum(u["value_sats"] for u in utxos)
        outputs_with_change = payments + [change_template]
        fee_with_all = required_fee(utxos, outputs_with_change, fee_rate_sat_vb)
        if all_total >= total_payment + fee_with_all:
            raise PolicyViolationError(
                f"Cannot cover payment with max_inputs={max_inputs}. "
                f"Try increasing max_inputs or reducing payment amount."
            )

    total_available = sum(u["value_sats"] for u in selected)
    raise InsufficientFundsError(
        f"Insufficient funds: need at least {total_payment} sats for payments "
        f"plus fees, but only have {total_available} sats available "
        f"({'policy-limited to ' + str(max_inputs) + ' inputs' if max_inputs else 'all UTXOs'})"
    )


# ──────────────────────────────────────────────
# Strategy: Smallest-First (Coin Consolidation)
# ──────────────────────────────────────────────

def consolidate_select(
    utxos: list[dict],
    payments: list[dict],
    change_template: dict,
    fee_rate_sat_vb: float,
    max_inputs: int | None = None,
) -> list[dict]:
    """
    Consolidation strategy: pick smallest UTXOs first.

    Why? This reduces UTXO set size over time (cleans up "dust" UTXOs).
    Downside: uses more inputs → larger tx → higher fee.

    Useful when fee rates are low and you want to clean up your wallet.
    """
    total_payment = sum(p["value_sats"] for p in payments)

    # Sort smallest first
    sorted_utxos = sorted(utxos, key=lambda u: u["value_sats"])

    if max_inputs is not None:
        sorted_utxos = sorted_utxos[:max_inputs]

    selected = []
    total_selected = 0

    for utxo in sorted_utxos:
        selected.append(utxo)
        total_selected += utxo["value_sats"]

        fee_with_change = required_fee(selected, payments + [change_template], fee_rate_sat_vb)
        if total_selected >= total_payment + fee_with_change:
            return selected

        fee_no_change = required_fee(selected, payments, fee_rate_sat_vb)
        if total_selected >= total_payment + fee_no_change:
            return selected

    raise InsufficientFundsError(
        f"Insufficient funds after selecting all {len(selected)} available UTXOs."
    )


# ──────────────────────────────────────────────
# Branch and Bound (BnB)
# ──────────────────────────────────────────────
BNB_MAX_TRIES = 100_000

def bnb_select(utxos, payments, change_template, fee_rate_sat_vb, max_inputs=None):
    """Branch and Bound: find exact-match (zero-change) input set; fall back to greedy."""
    sorted_utxos = sorted(utxos, key=lambda u: u["value_sats"], reverse=True)
    if max_inputs is not None:
        sorted_utxos = sorted_utxos[:max_inputs]

    total_payment = sum(p["value_sats"] for p in payments)
    n = len(sorted_utxos)
    suffix_sum = [0] * (n + 1)
    for i in range(n - 1, -1, -1):
        suffix_sum[i] = suffix_sum[i + 1] + sorted_utxos[i]["value_sats"]

    # Estimate marginal input fee
    avg_input_fee = 68  # ~P2WPKH input vbytes fallback
    if n > 0:
        try:
            dummy = sorted_utxos[:1]
            avg_input_fee = (
                required_fee(dummy + [sorted_utxos[0]], payments, fee_rate_sat_vb)
                - required_fee(dummy, payments, fee_rate_sat_vb)
            )
        except Exception:
            pass

    best_selection = []
    tries = 0

    def dfs(index, current_selected, current_value, current_fee):
        nonlocal best_selection, tries
        if tries > BNB_MAX_TRIES:
            return
        tries += 1
        target = total_payment + current_fee
        if current_value == target:
            best_selection = list(current_selected)
            return
        if current_value > target + DUST_THRESHOLD:
            return
        if index >= n or current_value + suffix_sum[index] < target:
            return
        utxo = sorted_utxos[index]
        current_selected.append(utxo)
        dfs(index + 1, current_selected, current_value + utxo["value_sats"], current_fee + avg_input_fee)
        current_selected.pop()
        if best_selection:
            return
        dfs(index + 1, current_selected, current_value, current_fee)

    initial_fee = required_fee([], payments, fee_rate_sat_vb) if sorted_utxos else 0
    dfs(0, [], 0, initial_fee)

    if best_selection:
        sel_total = sum(u["value_sats"] for u in best_selection)
        exact_fee = required_fee(best_selection, payments, fee_rate_sat_vb)
        if sel_total >= total_payment + exact_fee:
            return best_selection

    return greedy_select(utxos, payments, change_template, fee_rate_sat_vb, max_inputs)


# ──────────────────────────────────────────────
# Knapsack / DP
# ──────────────────────────────────────────────
import math as _math

KNAPSACK_MAX_UTXOS = 200
KNAPSACK_BUCKET = 1_000

def knapsack_select(utxos, payments, change_template, fee_rate_sat_vb, max_inputs=None):
    """Knapsack DP: find minimum-input-count set covering the target."""
    total_payment = sum(p["value_sats"] for p in payments)
    sorted_utxos = sorted(utxos, key=lambda u: u["value_sats"], reverse=True)
    if max_inputs is not None:
        sorted_utxos = sorted_utxos[:max_inputs]
    sorted_utxos = sorted_utxos[:KNAPSACK_MAX_UTXOS]

    if not sorted_utxos:
        return greedy_select(utxos, payments, change_template, fee_rate_sat_vb, max_inputs)

    fee_estimate = required_fee(sorted_utxos[:1], payments + [change_template], fee_rate_sat_vb)
    target = total_payment + fee_estimate
    B = KNAPSACK_BUCKET
    max_bucket = _math.ceil(sum(u["value_sats"] for u in sorted_utxos) / B)
    target_bucket = _math.ceil(target / B)

    if target_bucket > max_bucket:
        return greedy_select(utxos, payments, change_template, fee_rate_sat_vb, max_inputs)

    INF = float("inf")
    dp = [INF] * (max_bucket + 1)
    parent = [None] * (max_bucket + 1)
    dp[0] = 0

    for i, utxo in enumerate(sorted_utxos):
        val_bucket = _math.ceil(utxo["value_sats"] / B)
        for b in range(max_bucket, val_bucket - 1, -1):
            prev = b - val_bucket
            if dp[prev] + 1 < dp[b]:
                dp[b] = dp[prev] + 1
                parent[b] = (i, prev)

    best_bucket = next((b for b in range(target_bucket, max_bucket + 1) if dp[b] < INF), None)
    if best_bucket is None:
        return greedy_select(utxos, payments, change_template, fee_rate_sat_vb, max_inputs)

    selected_indices, b = [], best_bucket
    while parent[b] is not None:
        idx, prev_b = parent[b]
        selected_indices.append(idx)
        b = prev_b

    selected = [sorted_utxos[i] for i in selected_indices]
    if not selected:
        return greedy_select(utxos, payments, change_template, fee_rate_sat_vb, max_inputs)

    sel_total = sum(u["value_sats"] for u in selected)
    if (sel_total >= total_payment + required_fee(selected, payments + [change_template], fee_rate_sat_vb) or
            sel_total >= total_payment + required_fee(selected, payments, fee_rate_sat_vb)):
        return selected

    return greedy_select(utxos, payments, change_template, fee_rate_sat_vb, max_inputs)


# ──────────────────────────────────────────────
# Strategy dispatcher
# ──────────────────────────────────────────────

STRATEGIES = {
    "greedy":      greedy_select,
    "bnb":         bnb_select,
    "knapsack":    knapsack_select,
    "consolidate": consolidate_select,
}


def select_coins(
    utxos: list[dict],
    payments: list[dict],
    change_template: dict,
    fee_rate_sat_vb: float,
    max_inputs: int | None = None,
    strategy: str = "greedy",
) -> tuple[list[dict], str]:
    """
    Select coins using the specified strategy.

    Returns:
        (selected_utxos, strategy_name_used)
    """
    fn = STRATEGIES.get(strategy, greedy_select)
    selected = fn(
        utxos=utxos,
        payments=payments,
        change_template=change_template,
        fee_rate_sat_vb=fee_rate_sat_vb,
        max_inputs=max_inputs,
    )
    return selected, strategy if strategy in STRATEGIES else "greedy"


# ──────────────────────────────────────────────────────────────────────────────
# Strategy scorer + auto-selector
# ──────────────────────────────────────────────────────────────────────────────

def score_selection(
    selected: list[dict],
    payments: list[dict],
    change_template: dict,
    fee_rate_sat_vb: float,
) -> dict:
    """
    Score a coin selection result across several metrics.
    Lower score = better (fee-optimal, no dust, fewer inputs).

    Returns a dict with all metrics plus a composite score.
    """
    from app.fee import compute_fee_and_change, DUST_THRESHOLD, estimate_vbytes

    total_in = sum(u["value_sats"] for u in selected)
    total_pay = sum(p["value_sats"] for p in payments)

    try:
        fee_sats, change_val, vbytes = compute_fee_and_change(
            selected_inputs=selected,
            payments=payments,
            change_template=change_template,
            fee_rate_sat_vb=fee_rate_sat_vb,
        )
    except Exception:
        return {"ok": False, "score": float("inf")}

    change_val = change_val or 0  # None means send-all / no change output
    has_change = change_val > 0
    dust_change = has_change and change_val < DUST_THRESHOLD
    n_inputs = len(selected)

    # ── Composite score (lower = better) ────────────────────────────────────
    # Weighted sum of normalised metrics:
    #   40% fee paid (minimise overpaying)
    #   30% tx size in vbytes (smaller = cheaper + faster)
    #   20% input count (fewer = more private, smaller tx)
    #   10% dust penalty (hard penalise dust change)
    score = (
        fee_sats * 0.40
        + vbytes * 30 * 0.30       # scale vbytes to sat-comparable magnitude
        + n_inputs * 500 * 0.20    # each extra input ≈ 500-sat penalty
        + (100_000 if dust_change else 0) * 0.10
    )

    return {
        "ok": True,
        "fee_sats": fee_sats,
        "vbytes": vbytes,
        "n_inputs": n_inputs,
        "change_sats": change_val,
        "has_change": has_change,
        "dust_change": dust_change,
        "score": round(score, 2),
    }


def compare_all_strategies(
    utxos: list[dict],
    payments: list[dict],
    change_template: dict,
    fee_rate_sat_vb: float,
    max_inputs: int | None = None,
) -> dict:
    """
    Run all strategies, score each one, pick the best.

    Returns:
        {
          "best": "bnb",
          "results": {
            "greedy":     { "ok": True/False, "selected": [...], ...metrics },
            "bnb":        { ... },
            "knapsack":   { ... },
            "consolidate":{ ... },
          }
        }
    """
    results = {}

    for name, fn in STRATEGIES.items():
        try:
            selected = fn(
                utxos=utxos,
                payments=payments,
                change_template=change_template,
                fee_rate_sat_vb=fee_rate_sat_vb,
                max_inputs=max_inputs,
            )
            metrics = score_selection(selected, payments, change_template, fee_rate_sat_vb)
            results[name] = {**metrics, "selected": selected}
        except (InsufficientFundsError, PolicyViolationError) as e:
            results[name] = {"ok": False, "score": float("inf"), "error": str(e), "selected": []}
        except Exception as e:
            results[name] = {"ok": False, "score": float("inf"), "error": str(e), "selected": []}

    # Pick best = lowest score among ok results
    ok_results = {k: v for k, v in results.items() if v.get("ok")}
    if not ok_results:
        best = None
    else:
        best = min(ok_results, key=lambda k: ok_results[k]["score"])

    return {"best": best, "results": results}


def select_coins(
    utxos: list[dict],
    payments: list[dict],
    change_template: dict,
    fee_rate_sat_vb: float,
    max_inputs: int | None = None,
    strategy: str = "auto",
) -> tuple[list[dict], str, dict]:
    """
    Select coins using the specified strategy (or auto-pick the best).

    Args:
        strategy: "auto" | "greedy" | "bnb" | "knapsack" | "consolidate"

    Returns:
        (selected_utxos, strategy_name_used, comparison_dict)
        comparison_dict is populated for "auto"; empty dict for explicit strategies.
    """
    comparison = {}

    if strategy == "auto" or strategy not in STRATEGIES:
        comp = compare_all_strategies(utxos, payments, change_template, fee_rate_sat_vb, max_inputs)
        comparison = comp["results"]
        best = comp["best"]
        if best is None:
            raise InsufficientFundsError("No strategy could cover payments + fees.")
        selected = comparison[best]["selected"]
        return selected, best, comparison

    # Explicit strategy
    fn = STRATEGIES[strategy]
    selected = fn(
        utxos=utxos,
        payments=payments,
        change_template=change_template,
        fee_rate_sat_vb=fee_rate_sat_vb,
        max_inputs=max_inputs,
    )
    return selected, strategy, {}