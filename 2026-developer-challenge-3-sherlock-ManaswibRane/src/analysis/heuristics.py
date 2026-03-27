"""
Bitcoin chain analysis heuristics.
Each heuristic returns a dict with at minimum {"detected": bool}.
"""
from typing import Dict, List, Any
from collections import defaultdict, Counter


# ── CIOH ────────────────────────────────────────────────────────────────────
def heuristic_cioh(tx: dict, block_ctx: dict) -> dict:
    if tx.get('is_coinbase'):
        return {"detected": False, "input_count": 1, "reason": "coinbase"}
    vin = tx.get('vin', [])
    input_count = len(vin)
    if input_count <= 1:
        return {"detected": False, "input_count": input_count}
    input_types = set(v.get('script_type', 'unknown') for v in vin
                      if v.get('script_type') not in ('unknown', ''))
    mixed_types = len(input_types) > 1
    return {
        "detected": True,
        "input_count": input_count,
        "mixed_input_types": mixed_types,
        "confidence": "medium" if mixed_types else "high",
    }


# ── Change Detection ─────────────────────────────────────────────────────────
def heuristic_change_detection(tx: dict, block_ctx: dict) -> dict:
    if tx.get('is_coinbase'):
        return {"detected": False}
    vout = tx.get('vout', [])
    vin = tx.get('vin', [])
    if len(vout) < 2:
        return {"detected": False}
    input_types = [v.get('script_type', '') for v in vin
                   if v.get('script_type') not in ('', 'coinbase', 'unknown')]
    if not input_types:
        input_types = [v.get('script_type', 'unknown') for v in vin]
    type_counts = Counter(input_types)
    dominant_type = type_counts.most_common(1)[0][0] if type_counts else None
    spendable = [o for o in vout if o.get('script_type') != 'op_return']
    if len(spendable) < 2:
        return {"detected": False}
    ROUND_THRESHOLDS = [100_000_000, 10_000_000, 1_000_000, 100_000, 10_000]
    if dominant_type and dominant_type not in ('unknown', ''):
        matching = [o for o in spendable if o.get('script_type') == dominant_type]
        non_matching = [o for o in spendable if o.get('script_type') != dominant_type]
        if len(matching) == 1 and len(non_matching) >= 1:
            change_out = matching[0]
            payment_is_round = any(
                o['value_sats'] % t == 0
                for o in non_matching for t in ROUND_THRESHOLDS
                if o['value_sats'] >= t
            )
            return {
                "detected": True,
                "likely_change_index": change_out['n'],
                "method": "script_type_match",
                "confidence": "high" if payment_is_round else "medium",
                "change_value_sats": change_out['value_sats'],
            }
    round_outputs, non_round_outputs = [], []
    for o in spendable:
        is_round = any(o['value_sats'] % t == 0 for t in ROUND_THRESHOLDS if o['value_sats'] >= t)
        (round_outputs if is_round else non_round_outputs).append(o)
    if len(round_outputs) >= 1 and len(non_round_outputs) == 1:
        change_out = non_round_outputs[0]
        return {
            "detected": True,
            "likely_change_index": change_out['n'],
            "method": "round_number",
            "confidence": "medium",
            "change_value_sats": change_out['value_sats'],
        }
    if len(spendable) == 2:
        change_out = sorted(spendable, key=lambda o: o['value_sats'], reverse=True)[0]
        return {
            "detected": True,
            "likely_change_index": change_out['n'],
            "method": "value_analysis",
            "confidence": "low",
            "change_value_sats": change_out['value_sats'],
        }
    return {"detected": False}


# ── CoinJoin ─────────────────────────────────────────────────────────────────
def heuristic_coinjoin(tx: dict, block_ctx: dict) -> dict:
    if tx.get('is_coinbase'):
        return {"detected": False}
    vin = tx.get('vin', [])
    vout = tx.get('vout', [])
    if len(vin) < 3 or len(vout) < 3:
        return {"detected": False}
    spendable = [o for o in vout if o.get('script_type') != 'op_return']
    value_counts = Counter(o['value_sats'] for o in spendable)
    equal_value_count, equal_value_sats = 0, 0
    for val, cnt in value_counts.items():
        if cnt >= 2 and val > 0 and cnt > equal_value_count:
            equal_value_count, equal_value_sats = cnt, val
    if equal_value_count < 2:
        return {"detected": False}
    equal_ratio = equal_value_count / len(spendable) if spendable else 0
    if equal_ratio < 0.3:
        return {"detected": False}
    input_types = set(v.get('script_type', 'unknown') for v in vin)
    mixed = len(input_types) > 1
    return {
        "detected": True,
        "equal_value_output_count": equal_value_count,
        "equal_value_sats": equal_value_sats,
        "input_count": len(vin),
        "output_count": len(vout),
        "mixed_inputs": mixed,
        "confidence": "high" if mixed and equal_ratio > 0.5 else "medium",
    }


# ── Consolidation ────────────────────────────────────────────────────────────
def heuristic_consolidation(tx: dict, block_ctx: dict) -> dict:
    if tx.get('is_coinbase'):
        return {"detected": False}
    vin = tx.get('vin', [])
    vout = tx.get('vout', [])
    spendable = [o for o in vout if o.get('script_type') != 'op_return']
    if len(vin) < 3 or len(spendable) > 2:
        return {"detected": False}
    ROUND_THRESHOLDS = [100_000_000, 10_000_000, 1_000_000, 100_000, 10_000]
    has_round = any(
        o['value_sats'] % t == 0
        for o in spendable for t in ROUND_THRESHOLDS if o['value_sats'] >= t
    )
    if has_round and len(vin) < 5 and len(spendable) == 2:
        return {"detected": False}
    input_types = set(v.get('script_type', 'unknown') for v in vin
                      if v.get('script_type') not in ('', 'coinbase'))
    same_type = len(input_types) == 1
    return {
        "detected": True,
        "input_count": len(vin),
        "output_count": len(spendable),
        "same_input_type": same_type,
        "confidence": "high" if same_type and len(vin) >= 5 else "medium",
    }


# ── Self-Transfer ────────────────────────────────────────────────────────────
def heuristic_self_transfer(tx: dict, block_ctx: dict) -> dict:
    if tx.get('is_coinbase'):
        return {"detected": False}
    vin = tx.get('vin', [])
    vout = tx.get('vout', [])
    spendable = [o for o in vout if o.get('script_type') != 'op_return']
    if not spendable:
        return {"detected": False}
    input_types = set(v.get('script_type', 'unknown') for v in vin
                      if v.get('script_type') not in ('', 'coinbase', 'unknown'))
    output_types = set(o.get('script_type', 'unknown') for o in spendable
                       if o.get('script_type') not in ('', 'unknown'))
    if not input_types or not output_types:
        return {"detected": False}
    if not output_types.issubset(input_types):
        return {"detected": False}
    ROUND_THRESHOLDS = [100_000_000, 10_000_000, 1_000_000, 100_000, 10_000]
    has_round = any(
        o['value_sats'] % t == 0
        for o in spendable for t in ROUND_THRESHOLDS if o['value_sats'] >= t
    )
    if has_round:
        return {"detected": False}
    return {"detected": True, "input_types": list(input_types), "output_types": list(output_types), "confidence": "medium"}


# ── Round Number Payment ─────────────────────────────────────────────────────
def heuristic_round_number_payment(tx: dict, block_ctx: dict) -> dict:
    if tx.get('is_coinbase'):
        return {"detected": False}
    ROUND_THRESHOLDS = [100_000_000, 10_000_000, 1_000_000, 100_000, 10_000]
    vout = tx.get('vout', [])
    round_outputs = []
    for o in vout:
        if o.get('script_type') == 'op_return':
            continue
        for t in ROUND_THRESHOLDS:
            if o['value_sats'] >= t and o['value_sats'] % t == 0:
                round_outputs.append({"index": o['n'], "value_sats": o['value_sats'], "threshold": t})
                break
    if not round_outputs:
        return {"detected": False}
    return {"detected": True, "round_outputs": round_outputs, "count": len(round_outputs)}


# ── OP_RETURN Analysis ───────────────────────────────────────────────────────
def heuristic_op_return(tx: dict, block_ctx: dict) -> dict:
    from core.script import decode_op_return
    vout = tx.get('vout', [])
    op_returns = []
    for o in vout:
        if o.get('script_type') == 'op_return':
            script_hex = o.get('script_pubkey_hex', '')
            try:
                script_bytes = bytes.fromhex(script_hex)
                data_hex, data_utf8, protocol = decode_op_return(script_bytes)
            except Exception:
                data_hex, data_utf8, protocol = '', None, 'unknown'
            op_returns.append({
                "index": o['n'], "protocol": protocol,
                "data_hex": data_hex[:64],
                "data_utf8": data_utf8[:64] if data_utf8 else None,
            })
    if not op_returns:
        return {"detected": False}
    return {"detected": True, "op_return_outputs": op_returns, "count": len(op_returns)}


# ── Address Reuse ────────────────────────────────────────────────────────────
def heuristic_address_reuse(tx: dict, block_ctx: dict) -> dict:
    txid = tx.get('txid', '')
    vin = tx.get('vin', [])
    vout = tx.get('vout', [])
    input_scripts = {v.get('prevout', {}).get('script_pubkey_hex', '') for v in vin} - {''}
    output_scripts = {o.get('script_pubkey_hex', '') for o in vout
                      if o.get('script_type') != 'op_return'} - {''}
    intra_reuse = input_scripts & output_scripts
    block_script_to_txids = block_ctx.get('script_to_txids', {})
    reused_in_block = [
        s[:40] for s in output_scripts
        if len(block_script_to_txids.get(s, [])) > 1 and txid in block_script_to_txids.get(s, [])
    ]
    if not intra_reuse and not reused_in_block:
        return {"detected": False}
    return {
        "detected": True,
        "intra_tx_reuse_count": len(intra_reuse),
        "block_reuse_count": len(reused_in_block),
        "reused_scripts": list(intra_reuse)[:3],
    }


# ── Peeling Chain ────────────────────────────────────────────────────────────
def heuristic_peeling_chain(tx: dict, block_ctx: dict) -> dict:
    if tx.get('is_coinbase'):
        return {"detected": False}
    vout = tx.get('vout', [])
    spendable = [o for o in vout if o.get('script_type') != 'op_return']
    if len(spendable) != 2:
        return {"detected": False}
    vals = [o['value_sats'] for o in spendable]
    if min(vals) == 0:
        return {"detected": False}
    ratio = max(vals) / min(vals)
    if ratio < 5:
        return {"detected": False}
    txid = tx.get('txid', '')
    chain_continues = txid in block_ctx.get('txids_spent_in_block', set())
    small_idx = spendable[0]['n'] if vals[0] < vals[1] else spendable[1]['n']
    large_idx = spendable[0]['n'] if vals[0] > vals[1] else spendable[1]['n']
    return {
        "detected": True,
        "payment_index": small_idx,
        "change_index": large_idx,
        "value_ratio": round(ratio, 2),
        "chain_continues": chain_continues,
        "confidence": "high" if chain_continues else "medium",
    }


# ── Batch Payment Detection ──────────────────────────────────────────────────
def heuristic_batch_payment(tx: dict, block_ctx: dict) -> dict:
    """
    Batch payment: 1-3 inputs, 4+ spendable outputs.
    Typical of exchanges, payroll systems, or payout services.
    """
    if tx.get('is_coinbase'):
        return {"detected": False}
    vin = tx.get('vin', [])
    vout = tx.get('vout', [])
    spendable = [o for o in vout if o.get('script_type') != 'op_return']
    if len(vin) > 3 or len(spendable) < 4:
        return {"detected": False}
    output_types = Counter(o.get('script_type', 'unknown') for o in spendable)
    dominant_out_type = output_types.most_common(1)[0][0] if output_types else None
    homogeneous = output_types.most_common(1)[0][1] / len(spendable) >= 0.8 if output_types else False
    return {
        "detected": True,
        "input_count": len(vin),
        "output_count": len(spendable),
        "dominant_output_type": dominant_out_type,
        "homogeneous_outputs": homogeneous,
        "confidence": "high" if homogeneous and len(spendable) >= 6 else "medium",
    }


# ── Dust Detection ───────────────────────────────────────────────────────────
def heuristic_dust_detection(tx: dict, block_ctx: dict) -> dict:
    """
    Detect dust outputs (< 546 sats for P2PKH, < 294 for P2WPKH, < 330 for P2TR).
    Dust outputs are uneconomical to spend and may be used for tracking/spam.
    """
    DUST_LIMITS = {'p2pkh': 546, 'p2sh': 540, 'p2wpkh': 294, 'p2wsh': 330, 'p2tr': 330, 'unknown': 546}
    DEFAULT_DUST = 546
    vout = tx.get('vout', [])
    dust_outputs = []
    for o in vout:
        if o.get('script_type') == 'op_return':
            continue
        limit = DUST_LIMITS.get(o.get('script_type', 'unknown'), DEFAULT_DUST)
        if o['value_sats'] > 0 and o['value_sats'] < limit:
            dust_outputs.append({
                "index": o['n'],
                "value_sats": o['value_sats'],
                "dust_limit": limit,
                "script_type": o.get('script_type', 'unknown'),
            })
    if not dust_outputs:
        return {"detected": False}
    # Check if this looks like a dust attack (many tiny outputs to unrelated addresses)
    is_dust_attack = len(dust_outputs) >= 2
    return {
        "detected": True,
        "dust_outputs": dust_outputs,
        "count": len(dust_outputs),
        "possible_dust_attack": is_dust_attack,
        "confidence": "high" if is_dust_attack else "medium",
    }


# ── Output Position Analysis ─────────────────────────────────────────────────
def heuristic_output_position(tx: dict, block_ctx: dict) -> dict:
    """
    BIP69 lexicographic output ordering detection.
    Also checks if change is at index 0 (common wallet behaviour).
    Wallets that use BIP69 reveal their wallet software.
    """
    if tx.get('is_coinbase'):
        return {"detected": False}
    vout = tx.get('vout', [])
    spendable = [o for o in vout if o.get('script_type') != 'op_return']
    if len(spendable) < 2:
        return {"detected": False}

    # Check BIP69: outputs sorted by (value_sats ASC, script_pubkey_hex ASC)
    expected_bip69 = sorted(spendable, key=lambda o: (o['value_sats'], o.get('script_pubkey_hex', '')))
    is_bip69 = all(spendable[i]['n'] == expected_bip69[i]['n'] for i in range(len(spendable)))

    # Change at position 0 heuristic
    change_result = block_ctx.get('_change_cache', {}).get(tx.get('txid', ''))
    change_at_zero = False
    if not change_result:
        # Simple check: if first output matches input type
        vin = tx.get('vin', [])
        input_types = Counter(v.get('script_type', '') for v in vin if v.get('script_type') not in ('', 'coinbase'))
        if input_types and spendable:
            dominant = input_types.most_common(1)[0][0]
            change_at_zero = spendable[0].get('script_type') == dominant and len(spendable) >= 2

    if not is_bip69 and not change_at_zero:
        return {"detected": False}

    return {
        "detected": True,
        "bip69_ordering": is_bip69,
        "change_at_index_zero": change_at_zero,
        "output_count": len(spendable),
        "confidence": "medium",
        "note": "BIP69 reveals wallet software; change-at-zero is common wallet pattern",
    }


# ── Address Freshness Detection ───────────────────────────────────────────────
def heuristic_address_freshness(tx: dict, block_ctx: dict) -> dict:
    """
    Detect whether output addresses are 'fresh' (first appearance in this block)
    vs reused. Fresh outputs suggest good privacy hygiene; reused suggest poor.
    All-fresh outputs are typical of well-implemented wallets (HD wallet new address).
    """
    if tx.get('is_coinbase'):
        return {"detected": False}
    vout = tx.get('vout', [])
    spendable = [o for o in vout if o.get('script_type') != 'op_return']
    if not spendable:
        return {"detected": False}

    block_script_to_txids = block_ctx.get('script_to_txids', {})
    txid = tx.get('txid', '')

    fresh_outputs = []
    reused_outputs = []
    for o in spendable:
        s = o.get('script_pubkey_hex', '')
        txids_using = block_script_to_txids.get(s, [])
        # Fresh = only appears in this tx (count == 1 and it's this tx)
        if len(txids_using) <= 1:
            fresh_outputs.append(o['n'])
        else:
            reused_outputs.append(o['n'])

    all_fresh = len(reused_outputs) == 0
    all_reused = len(fresh_outputs) == 0

    return {
        "detected": True,
        "fresh_output_count": len(fresh_outputs),
        "reused_output_count": len(reused_outputs),
        "all_fresh": all_fresh,
        "all_reused": all_reused,
        "privacy_score": "good" if all_fresh else ("poor" if all_reused else "mixed"),
        "confidence": "medium",
    }


# ── Fee Pattern Analysis ──────────────────────────────────────────────────────
def heuristic_fee_pattern(tx: dict, block_ctx: dict) -> dict:
    """
    Analyse fee patterns to identify wallet software and behaviour:
    - Round fee amounts suggest fee estimation by round sat/vB (e.g. 10, 20, 50)
    - Very high fees may indicate CPFP (Child-Pays-For-Parent) or urgency
    - Near-zero fees suggest LN channel opens or test transactions
    - Fee rate relative to block median reveals priority intent
    """
    if tx.get('is_coinbase'):
        return {"detected": False}

    fee_sats = tx.get('fee_sats', 0)
    fee_rate = tx.get('fee_rate_sat_vb', 0.0)
    vbytes = tx.get('vbytes', 1)

    if fee_sats == 0 or fee_rate == 0:
        return {"detected": False}

    flags = []
    fee_type = "normal"

    # Round fee rate (suggests fee-rate-based estimation)
    if fee_rate == round(fee_rate) and fee_rate > 0:
        flags.append("round_fee_rate")

    # Round fee amount (suggests fee-amount-based estimation)
    if fee_sats % 100 == 0:
        flags.append("round_fee_amount")

    # Overpaying
    block_median = block_ctx.get('block_median_fee_rate', 0)
    if block_median > 0 and fee_rate > block_median * 3:
        flags.append("high_priority")
        fee_type = "high_priority"

    # Underpaying
    if block_median > 0 and fee_rate < block_median * 0.3:
        flags.append("low_priority")
        fee_type = "low_priority"

    # CPFP candidate: small tx with very high fee rate
    if vbytes < 200 and fee_rate > 50:
        flags.append("possible_cpfp")

    # Minimum fee (1 sat/vB) — test tx or special protocol
    if fee_rate <= 1.1:
        flags.append("minimum_fee")
        fee_type = "minimum"

    if not flags:
        return {"detected": False}

    return {
        "detected": True,
        "fee_sats": fee_sats,
        "fee_rate_sat_vb": fee_rate,
        "fee_type": fee_type,
        "flags": flags,
        "confidence": "medium",
    }


# ── Wallet Fingerprinting ─────────────────────────────────────────────────────
def heuristic_wallet_fingerprint(tx: dict, block_ctx: dict) -> dict:
    """
    Attempt to identify wallet software from transaction patterns:
    - Input/output script type combinations
    - Locktime values (some wallets set locktime = current block height for anti-fee-sniping)
    - RBF signaling (some wallets always/never signal RBF)
    - Version field (most use v1 or v2)
    - Sequence values (0xFFFFFFFD = RBF, 0xFFFFFFFE = no RBF/no timelock, 0xFFFFFFFF = legacy)
    """
    if tx.get('is_coinbase'):
        return {"detected": False}

    vin = tx.get('vin', [])
    vout = tx.get('vout', [])
    version = tx.get('version', 1)
    locktime = tx.get('locktime', 0)
    rbf = tx.get('rbf_signaling', False)
    vbytes = tx.get('vbytes', 0)

    signals = []
    wallet_hints = []

    # Anti-fee-sniping: locktime close to current block height
    # (locktime > 500000 is timestamp, < 500000 is block height)
    if 0 < locktime < 500_000:
        signals.append("locktime_block_height")
        wallet_hints.append("anti-fee-sniping (Bitcoin Core / modern wallet)")

    # Version 2 = OP_CHECKSEQUENCEVERIFY enabled
    if version == 2:
        signals.append("tx_version_2")

    # RBF signaling
    if rbf:
        signals.append("rbf_signaled")
        wallet_hints.append("RBF-aware wallet (Core, Electrum, etc.)")

    # All-segwit inputs
    input_types = [v.get('script_type', '') for v in vin]
    segwit_types = {'p2wpkh', 'p2wsh', 'p2tr', 'p2sh-p2wpkh'}
    if input_types and all(t in segwit_types for t in input_types):
        signals.append("all_segwit_inputs")

    # Pure Taproot wallet
    out_types = [o.get('script_type', '') for o in vout if o.get('script_type') != 'op_return']
    if input_types and out_types:
        if all(t == 'p2tr' for t in input_types if t) and all(t == 'p2tr' for t in out_types if t):
            signals.append("pure_taproot")
            wallet_hints.append("Taproot-native wallet")

    # Mixed legacy + segwit (older wallet upgrading)
    legacy_types = {'p2pkh', 'p2sh'}
    has_legacy = any(t in legacy_types for t in input_types)
    has_segwit = any(t in segwit_types for t in input_types)
    if has_legacy and has_segwit:
        signals.append("mixed_generation_inputs")
        wallet_hints.append("wallet migrating from legacy to SegWit")

    if not signals:
        return {"detected": False}

    return {
        "detected": True,
        "signals": signals,
        "wallet_hints": wallet_hints,
        "version": version,
        "locktime": locktime,
        "rbf": rbf,
        "confidence": "low",
        "note": "Fingerprinting is probabilistic; multiple signals increase accuracy",
    }


# ── Block Context ─────────────────────────────────────────────────────────────
def build_block_context(transactions: list) -> dict:
    script_to_txids: Dict[str, List[str]] = defaultdict(list)
    for tx in transactions:
        txid = tx.get('txid', '')
        for o in tx.get('vout', []):
            s = o.get('script_pubkey_hex', '')
            if s and o.get('script_type') != 'op_return':
                script_to_txids[s].append(txid)

    txids_spent_in_block: set = set()
    for tx in transactions:
        for v in tx.get('vin', []):
            spent_txid = v.get('txid', '')
            if spent_txid and spent_txid != '0' * 64:
                txids_spent_in_block.add(spent_txid)

    # Compute block median fee rate for fee pattern analysis
    fee_rates = [tx.get('fee_rate_sat_vb', 0) for tx in transactions
                 if not tx.get('is_coinbase') and tx.get('fee_rate_sat_vb', 0) > 0]
    block_median = 0.0
    if fee_rates:
        s = sorted(fee_rates)
        n = len(s)
        block_median = (s[n//2-1] + s[n//2]) / 2 if n % 2 == 0 else s[n//2]

    return {
        'script_to_txids': dict(script_to_txids),
        'txids_spent_in_block': txids_spent_in_block,
        'block_median_fee_rate': block_median,
    }


# ── Registry ─────────────────────────────────────────────────────────────────
HEURISTIC_REGISTRY = [
    ('cioh', heuristic_cioh),
    ('change_detection', heuristic_change_detection),
    ('coinjoin', heuristic_coinjoin),
    ('consolidation', heuristic_consolidation),
    ('self_transfer', heuristic_self_transfer),
    ('round_number_payment', heuristic_round_number_payment),
    ('op_return', heuristic_op_return),
    ('address_reuse', heuristic_address_reuse),
    ('peeling_chain', heuristic_peeling_chain),
    ('batch_payment', heuristic_batch_payment),
    ('dust_detection', heuristic_dust_detection),
    ('output_position', heuristic_output_position),
    ('address_freshness', heuristic_address_freshness),
    ('fee_pattern', heuristic_fee_pattern),
    ('wallet_fingerprint', heuristic_wallet_fingerprint),
]


def apply_heuristics(tx: dict, block_ctx: dict) -> dict:
    results = {}
    for hid, fn in HEURISTIC_REGISTRY:
        try:
            results[hid] = fn(tx, block_ctx)
        except Exception as e:
            results[hid] = {"detected": False, "error": str(e)}
    return results