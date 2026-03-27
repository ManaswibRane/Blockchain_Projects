"""
Fee rate statistics computation.
"""
import statistics
from typing import List


def compute_fee_stats(transactions: list) -> dict:
    """
    Compute fee rate statistics across non-coinbase transactions.
    Returns dict with min_sat_vb, max_sat_vb, median_sat_vb, mean_sat_vb.
    """
    rates = [
        tx['fee_rate_sat_vb']
        for tx in transactions
        if not tx.get('is_coinbase') and tx.get('fee_rate_sat_vb', 0) > 0
    ]

    if not rates:
        return {
            "min_sat_vb": 0.0,
            "max_sat_vb": 0.0,
            "median_sat_vb": 0.0,
            "mean_sat_vb": 0.0,
        }

    rates_sorted = sorted(rates)
    n = len(rates_sorted)
    if n % 2 == 0:
        median = (rates_sorted[n // 2 - 1] + rates_sorted[n // 2]) / 2
    else:
        median = rates_sorted[n // 2]

    result = {
        "min_sat_vb": round(min(rates_sorted), 4),
        "max_sat_vb": round(max(rates_sorted), 4),
        "median_sat_vb": round(median, 4),
        "mean_sat_vb": round(sum(rates) / len(rates), 4),
    }

    # Enforce constraint: min <= median <= max
    if result['min_sat_vb'] > result['median_sat_vb']:
        result['median_sat_vb'] = result['min_sat_vb']
    if result['median_sat_vb'] > result['max_sat_vb']:
        result['median_sat_vb'] = result['max_sat_vb']

    return result


def compute_script_type_distribution(transactions: list) -> dict:
    """
    Aggregate script type counts across all outputs in transactions.
    """
    dist = {}
    for tx in transactions:
        for o in tx.get('vout', []):
            st = o.get('script_type', 'unknown')
            dist[st] = dist.get(st, 0) + 1
    return dist