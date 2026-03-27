"""
Transaction classification based on heuristics results.
"""


def classify_transaction(tx: dict, heuristics: dict) -> str:
    """
    Classify transaction using priority order.
    Returns one of: coinjoin, consolidation, batch_payment, self_transfer,
                    simple_payment, unknown
    """
    if tx.get('is_coinbase'):
        return 'unknown'

    h = heuristics
    vin = tx.get('vin', [])
    vout = tx.get('vout', [])
    spendable_out = [o for o in vout if o.get('script_type') != 'op_return']

    n_in = len(vin)
    n_out = len(spendable_out)

    # 1. CoinJoin (highest specificity)
    if h.get('coinjoin', {}).get('detected'):
        return 'coinjoin'

    # 2. Consolidation (many-to-few)
    if h.get('consolidation', {}).get('detected'):
        return 'consolidation'

    # 3. Batch payment (few inputs, many outputs)
    if n_out >= 4 and n_in <= 3:
        return 'batch_payment'

    # 4. Self-transfer
    if h.get('self_transfer', {}).get('detected'):
        return 'self_transfer'

    # 5. Simple payment (1-2 inputs, 1-3 outputs, change detected or 1 output)
    if n_in <= 3 and n_out <= 3:
        if h.get('change_detection', {}).get('detected'):
            return 'simple_payment'
        if n_out == 1 and n_in >= 1:
            return 'simple_payment'

    # 6. Catch-all simple payment for 2-output transactions
    if n_out == 2 and n_in >= 1:
        return 'simple_payment'

    return 'unknown'