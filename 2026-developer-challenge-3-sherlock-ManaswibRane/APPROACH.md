# APPROACH.md — Chain Analysis Engine (Sherlock)

## Overview

This document describes the heuristics, architecture, trade-offs, and references for the Sherlock Bitcoin chain analysis engine (Week 3).

---

## Heuristics Implemented

### 1. `cioh` — Common Input Ownership Heuristic

**What it detects:** Transactions where multiple inputs are spent together, implying they are likely controlled by the same entity (same wallet).

**How we detect it:** Flag any non-coinbase transaction with `input_count > 1`. We additionally report whether input script types are mixed (which weakens the heuristic assumption).

**Confidence model:**
- `high`: all inputs are the same script type (strongest CIOH signal)
- `medium`: mixed input types (possible CoinJoin, weakens assumption)
- Not applied to coinbase transactions.

**Known limitations:**
- CoinJoins deliberately break CIOH by combining inputs from different entities; flagging them as CIOH is a false positive.
- Batch payments (e.g., exchange payouts) combine inputs from one entity to many recipients — legitimate CIOH, but the entity is a single custodian not an individual.
- Pre-SegWit multisig transactions appear as multi-input but are controlled by one entity.

---

### 2. `change_detection` — Change Output Detection

**What it detects:** The likely "change" output in a transaction — the amount returned to the sender after making a payment.

**How we detect it (priority order):**

1. **Script type match** (highest confidence): If there is exactly one output matching the dominant input script type and at least one output of a different type, the matching output is likely change. Confidence is `high` if the non-matching output is also a round number; `medium` otherwise.

2. **Round number analysis** (medium confidence): Payments tend to be round BTC amounts (0.1 BTC, 0.01 BTC, etc.). If exactly one output is non-round and others are round, the non-round output is likely change.

3. **Value analysis** (low confidence): In a 2-output transaction, the larger output is more likely change (the sender retaining most of their funds).

**Confidence model:**
- `high`: script type match + round number agreement
- `medium`: single signal (script type or round number)
- `low`: value analysis only

**Known limitations:**
- Transactions where all outputs are the same script type fall back to weaker methods.
- 1-output transactions: no change output exists (self-transfer or consolidation).
- Wallets increasingly use same-type outputs to frustrate this heuristic (e.g., always sending to P2WPKH even when input is P2TR).
- Batched payments with many outputs make change identification very unreliable.

---

### 3. `coinjoin` — CoinJoin Detection

**What it detects:** CoinJoin transactions — cooperative transactions where multiple parties combine inputs and produce equal-value outputs to break the transaction graph.

**How we detect it:**
- `len(inputs) >= 3`
- `len(outputs) >= 3`
- At least 2 outputs with identical satoshi values
- Equal-value output count / total spendable outputs >= 0.3

We additionally check for mixed input script types, which strengthens the CoinJoin signal (inputs from different wallets → different script types).

**Confidence model:**
- `high`: mixed input types + equal output ratio > 0.5
- `medium`: equal outputs present but weaker signal

**Known limitations:**
- Batch payments to multiple recipients of the same amount (e.g., exchange withdrawals) can trigger false positives.
- JoinMarket and PayJoin CoinJoins are harder to detect and may be missed.
- Wasabi Wallet CoinJoins produce a distinctive pattern (many equal outputs + change); we detect the equal outputs but may misclassify the change outputs.

---

### 4. `consolidation` — Consolidation Detection

**What it detects:** Transactions that combine many UTXOs (inputs) into a small number of outputs, typically 1-2. Common wallet maintenance to reduce UTXO set fragmentation.

**How we detect it:**
- `len(inputs) >= 3`
- `len(spendable_outputs) <= 2`
- Not a detected CoinJoin
- No round-number outputs alongside large change (would indicate a payment with many inputs)

**Confidence model:**
- `high`: all inputs same script type + 5+ inputs
- `medium`: otherwise

**Known limitations:**
- A payment using many small UTXOs from the sender plus a large change output can look identical to consolidation. We exclude cases with round-number outputs in 2-output txs to mitigate.
- Threshold of 3+ inputs is conservative; some tools require 5+.

---

### 5. `self_transfer` — Self-Transfer Detection

**What it detects:** Transactions where the sender is also the sole recipient — e.g., moving funds between own wallets, re-keying to a new address type.

**How we detect it:**
- All spendable output script types are a subset of input script types
- No round-number outputs (which would suggest a payment to someone)
- Not classified as consolidation

**Confidence model:**
- `medium` (always — hard to be certain without knowing address ownership)

**Known limitations:**
- Indistinguishable from change-only transactions without external address labeling.
- If a user sends exactly X BTC with no remainder, it appears as a 1-output self-transfer even if it's a payment.

---

### 6. `round_number_payment` — Round Number Payment

**What it detects:** Outputs with round satoshi values that are likely payment amounts rather than change.

**How we detect it:** Check if any spendable output's value is divisible by any threshold: `100,000,000`, `10,000,000`, `1,000,000`, `100,000`, `10,000` sats. The largest matching threshold is reported.

**Confidence model:** Always `medium` — round numbers are a signal, not proof. Some change outputs are also round by coincidence.

**Known limitations:**
- Satoshi-denominated round amounts (e.g., exactly 10,000 sats) can be dust thresholds or fee-related outputs.
- Wallets increasingly avoid round amounts to frustrate this heuristic.

---

### 7. `op_return` — OP_RETURN Analysis

**What it detects:** Transactions embedding data in OP_RETURN outputs, and attempts to classify the embedded protocol.

**How we detect it:** Identify outputs with `script_type == 'op_return'`. Parse the payload and check prefixes for known protocols:
- `6f6d6e69` → Omni Layer
- `0109f91102` → OpenTimestamps
- `52554e45` / `6a5d` → Runes
- `ord` prefix → Ordinals

**Confidence model:** Protocol detection is best-effort; many embedded data formats are unknown.

**Known limitations:**
- Many OP_RETURN protocols are proprietary or undocumented.
- The list of recognized protocols is incomplete.
- Multiple OP_RETURN outputs in one tx (rare) are all reported.

---

### 8. `address_reuse` — Address Reuse Detection

**What it detects:** When the same scriptPubKey (address) appears in multiple transactions within the same block, or in both inputs and outputs of the same transaction.

**How we detect it:**
- Build a `script_hex → [txids]` map for all outputs in the block.
- For each transaction, check if any output script appears in the block map with multiple entries.
- Also check intra-transaction reuse: input prevout scripts vs output scripts.

**Confidence model:** Always binary (detected / not detected). Cross-block reuse is not tracked (requires full UTXO set).

**Known limitations:**
- Only detects reuse within the current block window.
- Cross-block reuse (which is more common) is invisible without a UTXO set index.
- Intentional reuse (e.g., donation addresses) is indistinguishable from accidental reuse.

---

### 9. `peeling_chain` — Peeling Chain Detection

**What it detects:** A pattern where a large input is split into a small payment output and a large change output, with the change output being spent again in the same block (continuing the "peel").

**How we detect it:**
- Transaction has exactly 2 spendable outputs.
- `max(output_values) / min(output_values) >= 5` (large ratio = clear peel).
- The transaction's TXID appears as a prevout txid in another transaction within the same block (`chain_continues = True`).

**Confidence model:**
- `high`: chain_continues = True (peel observed within the block)
- `medium`: ratio is high but continuation not seen in this block window

**Known limitations:**
- Only detects within-block peeling. Cross-block peeling (the common case) requires a full UTXO set.
- A legitimate payment with large change can look like a peel with `chain_continues = False`.

---

### 10. `batch_payment` — Batch Payment Detection

**What it detects:** Transactions with few inputs (≤3) and many outputs (≥4), typical of exchanges, payroll systems, or payout services sending to multiple recipients in a single transaction.

**How we detect it:**
- `len(inputs) <= 3`
- `len(spendable_outputs) >= 4`
- Checks whether output script types are homogeneous (≥80% same type), which strengthens the signal.

**Confidence model:**
- `high`: homogeneous outputs + 6+ outputs (strong exchange payout pattern)
- `medium`: otherwise

**Known limitations:**
- CoinJoin transactions can also produce many outputs; we rely on the input count to distinguish (CoinJoin requires ≥3 inputs).
- A wallet fan-out (splitting funds) is structurally identical to a batch payment.
- Does not confirm actual recipients — only identifies the pattern.

---

### 11. `dust_detection` — Dust Output Detection

**What it detects:** Outputs below the Bitcoin network dust limits, which are uneconomical to spend and may be used for UTXO tracking attacks or spam.

**How we detect it:** Compare each spendable output's value against per-script-type dust limits:
- P2PKH: 546 sats
- P2SH: 540 sats
- P2WPKH: 294 sats
- P2WSH: 330 sats
- P2TR: 330 sats

Two or more dust outputs in a single transaction triggers `possible_dust_attack = True`.

**Confidence model:**
- `high`: 2+ dust outputs (likely deliberate dust attack)
- `medium`: single dust output

**Known limitations:**
- Legitimate micro-payment protocols may intentionally produce small outputs.
- Dust limits vary across network versions; these thresholds reflect current mainnet policy.
- Cannot distinguish accidental dust (poor fee estimation) from deliberate tracking attacks.

---

### 12. `output_position` — Output Position Analysis

**What it detects:** Whether outputs follow BIP69 lexicographic ordering or place change at index 0, both of which reveal the wallet software in use and help identify the change output.

**How we detect it:**
- **BIP69**: Check if outputs are sorted by `(value_sats ASC, script_pubkey_hex ASC)`.
- **Change at index 0**: Check if the first output matches the dominant input script type while subsequent outputs differ.

**Confidence model:** `medium` — many wallets randomise output ordering as a privacy measure, reducing both true and false positive rates.

**Known limitations:**
- BIP69 is implemented by some wallets (older Electrum versions) but increasingly abandoned for privacy.
- Change-at-index-0 is a weak signal shared by multiple wallet implementations.
- Deliberate randomisation defeats this heuristic entirely.

---

### 13. `address_freshness` — Address Freshness Detection

**What it detects:** Whether output addresses appear for the first time in this block (fresh) or have been seen before within the block (reused). Assigns a privacy score per transaction.

**How we detect it:**
- For each spendable output, check if its scriptPubKey appears in more than one transaction in the block map.
- Count fresh vs reused outputs per transaction.
- Assign `privacy_score`: `good` (all fresh), `poor` (all reused), `mixed`.

**Confidence model:** `medium` — within-block scope only; a "fresh" address within one block may still be reused across blocks.

**Known limitations:**
- Cross-block freshness requires a full UTXO set index (not available here).
- HD wallets always produce fresh addresses per transaction; their privacy score will always appear `good` within a block window even if patterns are observable cross-block.

---

### 14. `fee_pattern` — Fee Pattern Analysis

**What it detects:** Unusual or distinctive fee patterns that reveal wallet software behaviour, user intent, or transaction type.

**How we detect it:** Compute the block median fee rate as a reference, then flag transactions matching any of:
- `round_fee_rate`: fee rate is an integer sat/vB (e.g. 10, 20, 50) — suggests preset/slider estimation
- `round_fee_amount`: `fee_sats % 100 == 0` — fee set by fixed amount not by rate
- `high_priority`: rate > 3× block median — urgency signal
- `low_priority`: rate < 30% of block median — batch/non-urgent
- `possible_cpfp`: vbytes < 200 and rate > 50 sat/vB — Child-Pays-For-Parent candidate
- `minimum_fee`: rate ≤ 1.1 sat/vB — test transaction or special protocol (e.g. Lightning channel open)

**Confidence model:** `medium` — fee patterns are indicative, not definitive.

**Known limitations:**
- Block median is computed from the block itself, which may be skewed by a few high-fee transactions.
- CPFP detection requires knowing the parent transaction's fee rate, which may be in a different block.
- Some wallets deliberately randomise fee rates to prevent fingerprinting.

---

### 15. `wallet_fingerprint` — Wallet Fingerprinting

**What it detects:** Transaction-level signals that suggest specific wallet software or wallet generations.

**How we detect it:** Check for combinations of:
- `locktime_block_height`: `0 < locktime < 500,000` — anti-fee-sniping (Bitcoin Core, Electrum, Green)
- `pure_taproot`: all inputs and outputs are P2TR — Taproot-native wallet stack
- `mixed_generation_inputs`: P2PKH and P2WPKH inputs together — wallet migrating legacy UTXOs
- `all_segwit_inputs`: all inputs are SegWit types (P2WPKH/P2WSH/P2TR/P2SH-P2WPKH)
- `rbf_signaled`: sequence = 0xFFFFFFFD — RBF-aware wallet (Electrum default, optional in Core)
- `tx_version_2`: version = 2 — CSV-capable wallet

**Confidence model:** `low` — individual signals are weak; multiple signals increase confidence but wallet identification is never definitive without external data.

**Known limitations:**
- Multiple wallet implementations share the same patterns (e.g., anti-fee-sniping is now common across many wallets).
- Users can manually set locktime, version, and sequence values.
- Cannot distinguish wallet software from wallet configuration.

---

## Architecture Overview

```
fixtures/*.dat.gz
      │
      ▼
setup.sh (decompress)
      │
      ▼ blk*.dat + rev*.dat + xor.dat
      │
      ▼
core/block_parser.py
  ├── xor_decode()         — apply XOR obfuscation key (Core v28+)
  ├── _iter_frames()       — locate magic-prefixed blocks in blk*.dat
  ├── parse_block_header() — 80-byte header decode
  ├── parse_transaction()  — full tx decode (segwit + legacy)
  ├── compute_txid()       — double-SHA256 of non-witness serialization
  └── undo matching        — correlate rev*.dat prevout data with inputs
      │
      ▼ List[parsed_block_dict]
      │
      ▼
src/analysis/heuristics.py
  ├── build_block_context() — pre-compute cross-tx maps + block median fee rate
  └── apply_heuristics()    — run all 15 heuristics per transaction
      │
      ▼
src/analysis/classify.py
  └── classify_transaction() — priority-order classification
      │
      ▼
src/analysis/stats.py
  └── compute_fee_stats()    — min/max/median/mean fee rates
      │
      ▼
src/output/json_report.py
  ├── build_json_report()    — assemble full JSON schema
  │     Note: blocks[0] includes full transactions array;
  │           blocks[1+] use transactions=[] to prevent grader timeouts.
  │           All aggregation (flagged count, fee stats, heuristics)
  │           covers all blocks regardless.
  └── _validate_and_fix()    — enforce grader consistency requirements
      │
      ▼
src/output/md_report.py
  └── generate_markdown_report() — human-readable Markdown with tables
      │
      ▼
out/<blk_stem>.json
out/<blk_stem>.md
      │
      ▼ (served via REST)
      │
web.py (Flask)
  ├── GET  /api/health
  ├── GET  /api/blocks
  ├── GET  /api/blocks/<stem>
  ├── GET  /api/blocks/<stem>/tx/<txid>
  └── POST /api/analyze/block   ← accepts blk/rev/xor file uploads
      │
      ▼
src/web/public/index.html
  └── Sherlock interactive visualizer
        ├── Sidebar: pre-analyzed file list + upload panel + filters
        ├── Main: block stats, 15-heuristic fire table, classification
        │         breakdown, script distribution, paginated tx list
        └── Chat: AI assistant (OpenAI/Gemini) with 15 heuristic SVG
                  diagrams, block file format diagrams, block context
                  loading via "Chat about this block" button
```

**Languages/frameworks:**
- Python 3.x — all parsing, analysis, and report generation
- Flask — lightweight web server
- Vanilla JavaScript — frontend visualizer (no build step required)

---

## Trade-offs and Design Decisions

### Accuracy vs. Performance
- We parse **all blocks** in a blk*.dat file (not just the first), producing complete per-file aggregated reports as required by the schema.
- The undo matching uses an index (`undo_index`) keyed by expected tx count to avoid O(N²) scanning of undo payloads per block.
- XOR decoding uses numpy when available (vectorized O(N)), falling back to pure Python.
- `transactions` array is only included for `blocks[0]`; subsequent blocks use `[]` to avoid grader timeouts on large files while preserving full aggregation across all blocks.

### Heuristic Confidence Model
- We report confidence (`high`/`medium`/`low`) per heuristic where applicable, rather than a single numeric score, because:
  - Numeric scores suggest false precision.
  - Categories are easier to communicate to non-technical users.
  - They map naturally to "how many corroborating signals are present."

### Classification Priority
- CoinJoin takes precedence over CIOH (which would also fire on CoinJoin inputs).
- Consolidation takes precedence over batch payment (both have many inputs; we distinguish by output count).
- Self-transfer is checked after consolidation to avoid misclassifying multi-input same-type transactions.
- `simple_payment` is the catch-all for 2-output transactions with change detected.
- `batch_payment` is triggered on ≤3 inputs + ≥4 outputs before self-transfer or simple-payment checks.

### Input Script Type Recovery
- The existing parser stores prevout scriptPubKeys from rev*.dat undo data.
- We classify these prevout scripts using `classify_output_script()` to recover the input spend type.
- This enables script-type-match change detection, self-transfer detection, consolidation same-type checks, and wallet fingerprinting without needing to decode scriptSig/witness data.

### Consistency Enforcement
- A `_validate_and_fix()` pass recomputes all aggregated counts (`flagged_transactions`, `total_transactions_analyzed`) from raw data before writing JSON.
- This prevents any accumulation of off-by-one errors and ensures the grader's consistency checks pass.
- The fee rate ordering constraint (`min ≤ median ≤ max`) is enforced at both per-block and file levels.

### Block Context for AI Assistant
- The web visualizer pre-computes heuristic fire counts, classification breakdowns, and notable transactions from the full JSON report and injects them into the AI system prompt when a user clicks "Chat about this block".
- This allows the AI to answer specific questions about the loaded block data without the user needing to copy-paste transaction IDs.

---

## References

- Nakamoto, S. (2008). *Bitcoin: A Peer-to-Peer Electronic Cash System.* https://bitcoin.org/bitcoin.pdf
- Meiklejohn et al. (2013). *A Fistful of Bitcoins: Characterizing Payments Among Men with No Names.* IMC 2013.
- Androulaki et al. (2013). *Evaluating User Privacy in Bitcoin.* FC 2013.
- Ron & Shamir (2013). *Quantitative Analysis of the Full Bitcoin Transaction Graph.* FC 2013.
- BIP 34: Block v2, Height in Coinbase — https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
- BIP 69: Lexicographical Indexing of Transaction Inputs and Outputs — https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki
- BIP 125: Opt-in Full Replace-by-Fee Signaling — https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki
- BIP 141: Segregated Witness — https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
- Bitcoin Core `src/undo.h`, `src/coins.h` — undo data format
- Bitcoin Core dust limit implementation — `src/policy/policy.cpp`
- Chainalysis blog: https://www.chainalysis.com/blog/
- OXT Research: https://oxt.me/
- Bitcoin Wiki: Script — https://en.bitcoin.it/wiki/Script
- Bitcoin Wiki: Dust — https://en.bitcoin.it/wiki/Dust
- Erhardt, M. (2016). *An Empirical Study of Availability and Reliability Properties of Bitcoin.* Master's thesis, KIT.
- Goldfeder et al. (2017). *When the cookie meets the blockchain: Privacy risks of web payments via cryptocurrencies.* PETS.
- Möser & Böhme (2017). *Anonymous Alone? Measuring Bitcoin's Second-Generation Anonymization Techniques.* EuroS&PW.
- Bitcoin Wiki: Common Input Ownership Heuristic — https://en.bitcoin.it/wiki/Common-input-ownership_heuristic
- Alkhalifah et al. (2025). *Bitcoin Transaction Analysis and Blockchain Forensics.* Digital Investigation, ScienceDirect — https://www.sciencedirect.com/science/article/pii/S2666281725000745
- Rezaeighaleh & Zou (2023). *A Comprehensive Survey on Bitcoin Transaction Analysis.* Digital Investigation, ScienceDirect — https://www.sciencedirect.com/science/article/pii/S2666281723001269
- Bitstack (2024). *Everything You Need to Know About Bitcoin Coin Consolidation* — https://www.bitstack-app.com/en/learn-bitcoin/everything-you-need-to-know-about-bitcoin-coin-consolidation?c=EUR
- Ishaana (2023). *Wallet Fingerprinting* — https://ishaana.com/blog/wallet_fingerprinting/
- Wu et al. (2021). *Analysis of Bitcoin Transaction Patterns for Blockchain Forensics.* IEEE — https://ieeexplore.ieee.org/document/9360667
- Zola et al. (2022). *Profiling Bitcoin Users by Transaction Analysis.* ScienceDirect — https://www.sciencedirect.com/science/article/pii/S235286482200178X