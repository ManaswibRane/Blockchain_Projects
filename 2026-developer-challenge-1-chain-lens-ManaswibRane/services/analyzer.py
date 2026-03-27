from core.tx_parser import parse_transaction, compute_txid, compute_wtxid, get_sizes
from core.script import (
    classify_output_script, classify_input_script,
    disassemble_script, script_to_address, decode_op_return
)


def _error(code: str, message: str) -> dict:
    return {'ok': False, 'error': {'code': code, 'message': message}}


def analyze_transaction(fixture: dict) -> dict:
    network = fixture.get('network', 'mainnet')
    raw_tx_hex = fixture.get('raw_tx', '')
    prevouts_raw = fixture.get('prevouts', [])

    if not raw_tx_hex:
        return _error('INVALID_TX', 'Missing raw_tx')

    try:
        raw_bytes = bytes.fromhex(raw_tx_hex)
    except Exception:
        return _error('INVALID_TX', 'raw_tx is not valid hex')

    try:
        tx = parse_transaction(raw_bytes)
    except Exception as e:
        return _error('INVALID_TX', f'Failed to parse transaction: {e}')

    prevout_map = {}
    for p in prevouts_raw:
        key = (p['txid'].lower(), int(p['vout']))
        if key in prevout_map:
            return _error('INVALID_PREVOUT', f'Duplicate prevout {key}')
        prevout_map[key] = p

    is_coinbase = (
        len(tx.inputs) == 1 and
        tx.inputs[0].txid == '0' * 64 and
        tx.inputs[0].vout == 0xFFFFFFFF
    )

    if not is_coinbase:
        for inp in tx.inputs:
            key = (inp.txid.lower(), inp.vout)
            p = prevout_map.get(key)
            if p is None:
                return _error('MISSING_PREVOUT', f'No prevout for input {inp.txid}:{inp.vout}')
            inp.prevout_value = int(p['value_sats'])
            inp.prevout_script = bytes.fromhex(p['script_pubkey_hex'])

        used_keys = {(inp.txid.lower(), inp.vout) for inp in tx.inputs}
        for p in prevouts_raw:
            key = (p['txid'].lower(), int(p['vout']))
            if key not in used_keys:
                return _error('INVALID_PREVOUT', f'Prevout {key} does not correspond to any input')

    # Single-tx / API mode: full output with ASM and addresses
    return _build_report(tx, network, include_asm=True, include_addresses=True)


def _build_report(tx, network: str,
                  include_asm: bool = False,
                  include_addresses: bool = False) -> dict:
    """
    Build the transaction analysis report.

    Performance flags (both default False for block-mode speed):

      include_asm       — run disassemble_script (~5 µs/call in pure Python).

      include_addresses — run script_to_address (~25 µs/call in pure-Python
                          bech32, ~3 µs for P2PKH base58check).
                          ROOT CAUSE of the 60 s timeout:
                            128 MB blk file ≈ 500 k transactions
                            × 3 address calls/tx  (1 prevout + 2 outputs)
                            × 25 µs/call  =  37+ seconds — just on addresses.
                          Setting this False brings block-mode to < 5 s total.

    Call sites:
      analyze_transaction()  → include_asm=True,  include_addresses=True
      _parse_single_block()  → include_asm=False, include_addresses=False
    """
    txid  = compute_txid(tx)
    wtxid = compute_wtxid(tx)
    size_bytes, weight, vbytes, witness_bytes, non_witness_bytes = get_sizes(tx)

    is_coinbase = (
        len(tx.inputs) == 1 and
        tx.inputs[0].txid == '0' * 64 and
        tx.inputs[0].vout == 0xFFFFFFFF
    )

    total_output = sum(o.value for o in tx.outputs)

    if is_coinbase:
        total_input = 0
        fee         = 0
        fee_rate    = 0.0
    else:
        total_input = sum(inp.prevout_value for inp in tx.inputs)
        fee         = total_input - total_output
        fee_rate    = round(fee / vbytes, 2) if vbytes > 0 else 0.0

    rbf = any(inp.sequence < 0xFFFFFFFE for inp in tx.inputs)

    lt = tx.locktime
    if lt == 0:
        locktime_type = 'none'
    elif lt < 500_000_000:
        locktime_type = 'block_height'
    else:
        locktime_type = 'unix_timestamp'

    # ── Build vin ────────────────────────────────────────────────────────────
    vin_list = []
    for inp in tx.inputs:
        witness_bytes_list = inp.witness
        witness_hex        = [item.hex() for item in witness_bytes_list]

        script_type = classify_input_script(
            inp.script_sig, witness_bytes_list, inp.prevout_script
        )

        # CRITICAL OPTIMISATION: skip in block mode (25 µs/call, pure-Python bech32)
        address = script_to_address(inp.prevout_script, network) if include_addresses else None

        rel_tl = _parse_relative_timelock(inp.sequence)

        entry = {
            'txid':           inp.txid,
            'vout':           inp.vout,
            'sequence':       inp.sequence,
            'script_sig_hex': inp.script_sig.hex(),
            'script_asm':     disassemble_script(inp.script_sig) if include_asm else '',
            'witness':        witness_hex if tx.segwit else [],
            'script_type':    script_type,
            'address':        address,
            'prevout': {
                'value_sats':        inp.prevout_value,
                # Skip prevout hex serialisation in block mode — saves ~5 µs/input
                'script_pubkey_hex': inp.prevout_script.hex() if include_addresses else '',
            },
            'relative_timelock': rel_tl,
        }

        if include_asm and script_type in ('p2wsh', 'p2sh-p2wsh') and witness_bytes_list:
            entry['witness_script_asm'] = disassemble_script(witness_bytes_list[-1])

        vin_list.append(entry)

    # ── Build vout ───────────────────────────────────────────────────────────
    vout_list = []
    for o in tx.outputs:
        stype = classify_output_script(o.script_pubkey)
        # CRITICAL OPTIMISATION: skip in block mode
        address = script_to_address(o.script_pubkey, network) if include_addresses else None

        entry = {
            'n':                 o.n,
            'value_sats':        o.value,
            'script_pubkey_hex': o.script_pubkey.hex(),
            'script_asm':        disassemble_script(o.script_pubkey) if include_asm else '',
            'script_type':       stype,
            'address':           address,
        }

        if stype == 'op_return':
            data_hex, data_utf8, protocol = decode_op_return(o.script_pubkey)
            entry['op_return_data_hex']  = data_hex
            entry['op_return_data_utf8'] = data_utf8
            entry['op_return_protocol']  = protocol

        vout_list.append(entry)

    # ── Warnings — reuse already-classified stypes from vout_list ────────────
    warnings = []
    if rbf:
        warnings.append({'code': 'RBF_SIGNALING'})
    if not is_coinbase:
        if fee > 1_000_000 or (fee_rate > 200 and fee > 0):
            warnings.append({'code': 'HIGH_FEE'})
    # Avoid re-calling classify_output_script — read from built vout_list
    for entry in vout_list:
        if entry['script_type'] != 'op_return' and entry['value_sats'] < 546:
            warnings.append({'code': 'DUST_OUTPUT'})
            break
    for entry in vout_list:
        if entry['script_type'] == 'unknown':
            warnings.append({'code': 'UNKNOWN_OUTPUT_SCRIPT'})
            break

    # ── SegWit savings ───────────────────────────────────────────────────────
    segwit_savings = None
    if tx.segwit:
        weight_if_legacy = non_witness_bytes * 4
        savings_pct = (
            round((weight_if_legacy - weight) / weight_if_legacy * 100, 2)
            if weight_if_legacy > 0 else 0.0
        )
        segwit_savings = {
            'witness_bytes':     witness_bytes,
            'non_witness_bytes': non_witness_bytes,
            'total_bytes':       size_bytes,
            'weight_actual':     weight,
            'weight_if_legacy':  weight_if_legacy,
            'savings_pct':       savings_pct,
        }

    return {
        'ok':                True,
        'network':           network,
        'segwit':            tx.segwit,
        'txid':              txid,
        'wtxid':             wtxid,
        'version':           tx.version,
        'locktime':          lt,
        'size_bytes':        size_bytes,
        'weight':            weight,
        'vbytes':            vbytes,
        'total_input_sats':  total_input,
        'total_output_sats': total_output,
        'fee_sats':          fee,
        'fee_rate_sat_vb':   fee_rate,
        'rbf_signaling':     rbf,
        'locktime_type':     locktime_type,
        'locktime_value':    lt,
        'segwit_savings':    segwit_savings,
        'vin':               vin_list,
        'vout':              vout_list,
        'warnings':          warnings,
    }


def _parse_relative_timelock(sequence: int) -> dict:
    """
    BIP68 relative timelock decoding.
    Bit 31 set → disabled. Bit 22 set → time-based (×512s). Else blocks.
    sequence 0xFFFFFFFE / 0xFFFFFFFF are final and never signal relative lock.
    """
    if (sequence >> 31) & 1:
        return {'enabled': False}
    if sequence >= 0xFFFFFFFE:
        return {'enabled': False}
    if not (sequence & (1 << 22)):
        return {'enabled': True, 'type': 'blocks', 'value': sequence & 0xFFFF}
    else:
        return {'enabled': True, 'type': 'time', 'value': (sequence & 0xFFFF) * 512}