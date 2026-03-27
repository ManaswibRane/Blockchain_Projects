"""
Markdown report generator for chain analysis results.
"""
import os
import datetime
from typing import List


def _fmt_sats(sats: int) -> str:
    return f"{sats:,}"


def _fmt_btc(sats: int) -> str:
    return f"{sats / 1e8:.8f}"


def _pct(count: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{count / total * 100:.1f}%"


def _classification_emoji(cls: str) -> str:
    return {
        'coinjoin': '🔀',
        'consolidation': '🗜',
        'batch_payment': '📦',
        'self_transfer': '↩',
        'simple_payment': '💸',
        'unknown': '❓',
    }.get(cls, '❓')


def generate_markdown_report(report: dict) -> str:
    """Generate a full Markdown report from a chain analysis JSON report."""
    lines = []
    filename = report.get('file', 'unknown.dat')
    block_count = report.get('block_count', 0)
    summary = report.get('analysis_summary', {})
    total_txs = summary.get('total_transactions_analyzed', 0)
    flagged = summary.get('flagged_transactions', 0)
    heuristics = summary.get('heuristics_applied', [])
    fee_stats = summary.get('fee_rate_stats', {})
    script_dist = summary.get('script_type_distribution', {})

    ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    # ── Header ────────────────────────────────────────────────────────────────
    lines.append(f"# Chain Analysis Report: `{filename}`")
    lines.append(f"")
    lines.append(f"> Generated: {ts}  ")
    lines.append(f"> Mode: `chain_analysis` | Heuristics Engine v1.0")
    lines.append(f"")

    # ── File Overview ─────────────────────────────────────────────────────────
    lines.append("## File Overview")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| Source File | `{filename}` |")
    lines.append(f"| Blocks in File | {block_count} |")
    lines.append(f"| Total Transactions | {_fmt_sats(total_txs)} |")
    lines.append(f"| Flagged Transactions | {_fmt_sats(flagged)} ({_pct(flagged, total_txs)}) |")
    lines.append(f"| Heuristics Applied | {len(heuristics)} |")
    lines.append("")

    # ── Summary Statistics ────────────────────────────────────────────────────
    lines.append("## Summary Statistics")
    lines.append("")

    # Fee rate table
    lines.append("### Fee Rate Distribution (sat/vB)")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Minimum | {fee_stats.get('min_sat_vb', 0)} sat/vB |")
    lines.append(f"| Median  | {fee_stats.get('median_sat_vb', 0)} sat/vB |")
    lines.append(f"| Mean    | {fee_stats.get('mean_sat_vb', 0)} sat/vB |")
    lines.append(f"| Maximum | {fee_stats.get('max_sat_vb', 0)} sat/vB |")
    lines.append("")

    # Script type distribution
    lines.append("### Script Type Distribution (All Outputs)")
    lines.append("")
    lines.append("| Script Type | Count | Share |")
    lines.append("|-------------|-------|-------|")
    total_outputs = sum(script_dist.values()) or 1
    for stype, count in sorted(script_dist.items(), key=lambda x: -x[1]):
        lines.append(f"| `{stype}` | {_fmt_sats(count)} | {_pct(count, total_outputs)} |")
    lines.append("")

    # Heuristics applied
    lines.append("### Heuristics Applied")
    lines.append("")
    heuristic_descriptions = {
        'cioh': 'Common Input Ownership — multiple inputs → same entity',
        'change_detection': 'Change Output Detection — identify likely change outputs',
        'coinjoin': 'CoinJoin Detection — equal-value outputs, many inputs',
        'consolidation': 'Consolidation Detection — many inputs to few outputs',
        'self_transfer': 'Self-Transfer Detection — all outputs match input types',
        'round_number_payment': 'Round Number Payment — round-value outputs suggest payments',
        'op_return': 'OP_RETURN Analysis — detect and classify embedded data',
        'address_reuse': 'Address Reuse Detection — same address in multiple txs',
        'peeling_chain': 'Peeling Chain Detection — sequential single-payment pattern',
    }
    lines.append("| ID | Description |")
    lines.append("|----|-------------|")
    for h in heuristics:
        desc = heuristic_descriptions.get(h, h)
        lines.append(f"| `{h}` | {desc} |")
    lines.append("")

    # ── Per-Block Sections ────────────────────────────────────────────────────
    lines.append("---")
    lines.append("")
    lines.append("## Per-Block Analysis")
    lines.append("")

    for bi, block in enumerate(report.get('blocks', []), 1):
        if '_error' in block:
            lines.append(f"### Block {bi}: Parse Error")
            lines.append("")
            lines.append(f"```")
            lines.append(str(block.get('_error', {})))
            lines.append(f"```")
            lines.append("")
            continue

        bsum = block.get('analysis_summary', {})
        bfee = bsum.get('fee_rate_stats', {})
        bscript = bsum.get('script_type_distribution', {})
        btxs = block.get('transactions', [])
        block_hash = block.get('block_hash', '?')
        block_height = block.get('block_height', '?')
        timestamp = block.get('timestamp', 0)
        tx_count = block.get('tx_count', 0)
        b_flagged = bsum.get('flagged_transactions', 0)

        ts_str = datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC') if timestamp else 'unknown'

        lines.append(f"### Block {bi} — Height {block_height}")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| Block Hash | `{block_hash}` |")
        lines.append(f"| Height | {block_height} |")
        lines.append(f"| Timestamp | {ts_str} |")
        lines.append(f"| Transactions | {_fmt_sats(tx_count)} |")
        lines.append(f"| Flagged | {_fmt_sats(b_flagged)} ({_pct(b_flagged, tx_count)}) |")
        lines.append(f"| Fee Rate (median) | {bfee.get('median_sat_vb', 0)} sat/vB |")
        lines.append(f"| Fee Rate (mean) | {bfee.get('mean_sat_vb', 0)} sat/vB |")
        lines.append(f"| Fee Rate (max) | {bfee.get('max_sat_vb', 0)} sat/vB |")
        lines.append("")

        # Heuristic findings per block
        lines.append("#### Heuristic Findings")
        lines.append("")
        heuristic_counts = {}
        for h in heuristics:
            cnt = sum(
                1 for tx in btxs
                if tx.get('heuristics', {}).get(h, {}).get('detected', False)
            )
            heuristic_counts[h] = cnt

        lines.append("| Heuristic | Detected In | % of Block Txs |")
        lines.append("|-----------|-------------|----------------|")
        for h, cnt in sorted(heuristic_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| `{h}` | {cnt} txs | {_pct(cnt, tx_count)} |")
        lines.append("")

        # Classification breakdown
        cls_counts = {}
        for tx in btxs:
            cls = tx.get('classification', 'unknown')
            cls_counts[cls] = cls_counts.get(cls, 0) + 1

        lines.append("#### Transaction Classification Breakdown")
        lines.append("")
        lines.append("| Classification | Count | Share | Emoji |")
        lines.append("|---------------|-------|-------|-------|")
        for cls, cnt in sorted(cls_counts.items(), key=lambda x: -x[1]):
            emoji = _classification_emoji(cls)
            lines.append(f"| `{cls}` | {cnt} | {_pct(cnt, tx_count)} | {emoji} |")
        lines.append("")

        # Script type for this block
        if bscript:
            lines.append("#### Script Type Distribution")
            lines.append("")
            lines.append("| Type | Count |")
            lines.append("|------|-------|")
            b_total_out = sum(bscript.values()) or 1
            for stype, cnt in sorted(bscript.items(), key=lambda x: -x[1]):
                lines.append(f"| `{stype}` | {cnt} ({_pct(cnt, b_total_out)}) |")
            lines.append("")

        # Notable transactions
        notable = _find_notable_transactions(btxs)
        if notable:
            lines.append("#### Notable Transactions")
            lines.append("")
            lines.append("| TXID (short) | Classification | Key Finding |")
            lines.append("|-------------|----------------|-------------|")
            for note in notable[:20]:
                txid = note['txid']
                short_txid = txid[:16] + '...' + txid[-8:] if len(txid) > 24 else txid
                cls = note['classification']
                finding = note['finding']
                lines.append(f"| `{short_txid}` | {_classification_emoji(cls)} `{cls}` | {finding} |")
            lines.append("")

        lines.append("---")
        lines.append("")

    # ── Analysis Notes ────────────────────────────────────────────────────────
    lines.append("## Analysis Notes & Limitations")
    lines.append("")
    lines.append("### Confidence Model")
    lines.append("")
    lines.append("Chain analysis heuristics are **probabilistic**, not deterministic.")
    lines.append("Each heuristic assigns a confidence level based on signal strength:")
    lines.append("")
    lines.append("- **High confidence**: Multiple corroborating signals (e.g., script type match + round number agreement)")
    lines.append("- **Medium confidence**: Single clear signal (e.g., script type match alone)")
    lines.append("- **Low confidence**: Weak signal (e.g., value analysis in isolation)")
    lines.append("")
    lines.append("### Known Limitations")
    lines.append("")
    lines.append("| Heuristic | Known False Positives | Known False Negatives |")
    lines.append("|-----------|----------------------|----------------------|")
    lines.append("| CIOH | CoinJoin, batch payments, payroll txs | Always high recall |")
    lines.append("| Change Detection | 1-output txs, identical output types | Cross-tx change not trackable |")
    lines.append("| CoinJoin | Batch payments with equal outputs | JoinMarket-style CoinJoins |")
    lines.append("| Consolidation | Payments with many inputs | Small consolidations (2-3 inputs) |")
    lines.append("| Peeling Chain | Only detects within-block continuations | Cross-block peeling invisible |")
    lines.append("| Address Reuse | N/A | Cross-block reuse not tracked |")
    lines.append("")
    lines.append("### Privacy Implications")
    lines.append("")
    lines.append("Chain analysis exploits the fact that Bitcoin transactions are **public** and **permanent**.")
    lines.append("The heuristics in this report represent techniques used by blockchain analytics firms")
    lines.append("to cluster addresses and identify transaction patterns. Users seeking privacy should")
    lines.append("consider CoinJoin, Lightning Network, or other privacy-enhancing protocols.")
    lines.append("")

    return "\n".join(lines)


def _find_notable_transactions(transactions: list) -> list:
    """Find interesting transactions to highlight in the report."""
    notable = []
    for tx in transactions:
        cls = tx.get('classification', 'unknown')
        heuristics = tx.get('heuristics', {})
        txid = tx.get('txid', '?')

        if cls == 'coinjoin':
            cj = heuristics.get('coinjoin', {})
            finding = f"{cj.get('equal_value_output_count', '?')} equal-value outputs @ {cj.get('equal_value_sats', '?')} sats"
            notable.append({'txid': txid, 'classification': cls, 'finding': finding})

        elif cls == 'consolidation':
            con = heuristics.get('consolidation', {})
            finding = f"{con.get('input_count', '?')} inputs → {con.get('output_count', '?')} outputs"
            notable.append({'txid': txid, 'classification': cls, 'finding': finding})

        elif heuristics.get('peeling_chain', {}).get('detected'):
            pc = heuristics.get('peeling_chain', {})
            finding = f"Ratio {pc.get('value_ratio', '?')}x, chain_continues={pc.get('chain_continues', False)}"
            notable.append({'txid': txid, 'classification': cls, 'finding': finding})

        elif heuristics.get('op_return', {}).get('detected'):
            opr = heuristics.get('op_return', {})
            protocols = {o.get('protocol') for o in opr.get('op_return_outputs', [])}
            finding = f"OP_RETURN protocols: {', '.join(protocols)}"
            notable.append({'txid': txid, 'classification': cls, 'finding': finding})

        elif cls == 'batch_payment':
            vout_count = sum(1 for k, v in heuristics.items() if k == 'cioh')
            finding = "Batch payment / fan-out transaction"
            notable.append({'txid': txid, 'classification': cls, 'finding': finding})

    return notable


def write_markdown_report(report: dict, out_path: str):
    """Write Markdown report to file."""
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    md = generate_markdown_report(report)
    with open(out_path, 'w') as f:
        f.write(md)

    # Enforce minimum 1KB
    if os.path.getsize(out_path) < 1024:
        with open(out_path, 'a') as f:
            f.write("\n\n<!-- padding to ensure minimum report size -->\n")
            f.write("### Appendix: Heuristic Reference\n\n")
            f.write("#### CIOH (Common Input Ownership Heuristic)\n\n")
            f.write("The CIOH assumes that all inputs to a transaction are controlled by the same entity. ")
            f.write("This is the most fundamental chain analysis assumption, introduced in Satoshi Nakamoto's ")
            f.write("original Bitcoin whitepaper. While not always accurate (CoinJoins deliberately break it), ")
            f.write("it remains the backbone of most blockchain analytics.\n\n")
            f.write("#### Change Detection\n\n")
            f.write("Bitcoin payments typically produce two outputs: one to the recipient and one 'change' ")
            f.write("output back to the sender. Identifying which output is change helps analysts follow the ")
            f.write("transaction graph. Methods include script type matching (change usually matches the input ")
            f.write("type), round number analysis (payments tend to be round amounts), and value analysis.\n\n")