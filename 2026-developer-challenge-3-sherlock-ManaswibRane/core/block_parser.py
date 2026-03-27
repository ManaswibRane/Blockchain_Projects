import struct
import math
import traceback
from typing import List, Optional, Tuple
from collections import defaultdict
from core.utils import ByteReader, double_sha256, to_little_endian_hex, encode_varint
from core.tx_parser import parse_transaction, compute_txid, get_sizes
from core.script import classify_output_script

MAGIC_MAINNET = b'\xf9\xbe\xb4\xd9'
MAGIC_TESTNET = b'\x0b\x11\x09\x07'
MAGIC_SET = {MAGIC_MAINNET, MAGIC_TESTNET}


def xor_decode(data: bytes, key: bytes) -> bytes:
    if not key or all(b == 0 for b in key):
        return data
    try:
        import numpy as np
        arr = np.frombuffer(data, dtype=np.uint8)
        klen = len(key)
        key_tile = np.tile(np.frombuffer(key, dtype=np.uint8),
                           (len(data) + klen - 1) // klen)[:len(data)]
        return np.bitwise_xor(arr, key_tile).tobytes()
    except ImportError:
        pass
    klen = len(key)
    key_full = (key * ((len(data) + klen - 1) // klen))[:len(data)]
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key_full[i]
    return bytes(result)


def _iter_frames(data: bytes):
    pos = 0
    n = len(data)
    while pos + 8 <= n:
        if data[pos:pos + 4] in MAGIC_SET:
            size_val = struct.unpack_from('<I', data, pos + 4)[0]
            end = pos + 8 + size_val
            if end > n:
                break
            yield data[pos + 8:end]
            pos = end
        else:
            best = -1
            for m in (MAGIC_MAINNET, MAGIC_TESTNET):
                idx = data.find(m, pos)
                if idx != -1 and (best == -1 or idx < best):
                    best = idx
            if best == -1:
                break
            pos = best


def _read_compact_size(reader: ByteReader) -> int:
    b = reader.read(1)[0]
    if b < 0xfd: return b
    if b == 0xfd: return struct.unpack('<H', reader.read(2))[0]
    if b == 0xfe: return struct.unpack('<I', reader.read(4))[0]
    return struct.unpack('<Q', reader.read(8))[0]


def _read_compact_size_at(payload: bytes, pos: int = 0) -> int:
    b = payload[pos]
    if b < 0xfd: return b
    if b == 0xfd: return struct.unpack_from('<H', payload, pos + 1)[0]
    if b == 0xfe: return struct.unpack_from('<I', payload, pos + 1)[0]
    return struct.unpack_from('<Q', payload, pos + 1)[0]


def _read_varint_7bit(reader: ByteReader) -> int:
    n = 0
    while True:
        b = reader.read(1)[0]
        n = (n << 7) | (b & 0x7f)
        if b & 0x80:
            n += 1
        else:
            return n


def decompress_amount(x: int) -> int:
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e > 0:
        n *= 10
        e -= 1
    return n


def decompress_script(nsize: int, data: bytes) -> bytes:
    if nsize == 0x00:
        return bytes([0x76, 0xa9, 0x14]) + data + bytes([0x88, 0xac])
    if nsize == 0x01:
        return bytes([0xa9, 0x14]) + data + bytes([0x87])
    if nsize in (0x02, 0x03):
        return bytes([0x21, nsize]) + data + bytes([0xac])
    if nsize in (0x04, 0x05):
        return bytes([0x41, 0x02 + (nsize - 4)]) + data + bytes([0xac])
    return data


def _parse_undo_entry(reader: ByteReader) -> Tuple[int, bytes, int, bool]:
    nHeight = _read_varint_7bit(reader)
    fCoinBase = bool(reader.read(1)[0])
    value_sats = decompress_amount(_read_varint_7bit(reader))
    nsize = _read_varint_7bit(reader)
    if nsize == 0:
        body = reader.read(20)
        return value_sats, bytes([0x76, 0xa9, 0x14]) + body + bytes([0x88, 0xac]), nHeight, fCoinBase
    if nsize == 1:
        body = reader.read(20)
        return value_sats, bytes([0xa9, 0x14]) + body + bytes([0x87]), nHeight, fCoinBase
    if nsize in (2, 3):
        body = reader.read(32)
        return value_sats, bytes([0x21, nsize]) + body + bytes([0xac]), nHeight, fCoinBase
    if nsize in (4, 5):
        body = reader.read(32)
        return value_sats, bytes([0x41, 0x02 + (nsize - 4)]) + body + bytes([0xac]), nHeight, fCoinBase
    script_len = nsize - 6
    if reader.remaining() < script_len:
        raise ValueError(f"raw script underflow: need {script_len}, have {reader.remaining()}")
    return value_sats, reader.read(script_len), nHeight, fCoinBase


def _collect_undo_payloads(rev_data: bytes) -> List[bytes]:
    return list(_iter_frames(rev_data))


def _parse_undo_payload(payload: bytes, transactions: list) -> Optional[list]:
    reader = ByteReader(payload)
    try:
        txundo_count = _read_compact_size(reader)
        if txundo_count != len(transactions) - 1:
            return None
        parsed = []
        for tx_idx in range(txundo_count):
            inundo_count = _read_compact_size(reader)
            if inundo_count != len(transactions[tx_idx + 1].inputs):
                return None
            parsed.append([_parse_undo_entry(reader) for _ in range(inundo_count)])
        if reader.remaining() not in (0, 4):
            return None
        return parsed
    except Exception:
        return None


def parse_block_header(data: bytes) -> dict:
    version = struct.unpack_from('<i', data, 0)[0]
    prev_hash = to_little_endian_hex(data[4:36])
    merkle = to_little_endian_hex(data[36:68])
    timestamp = struct.unpack_from('<I', data, 68)[0]
    bits = data[72:76].hex()
    nonce = struct.unpack_from('<I', data, 76)[0]
    bhash = to_little_endian_hex(double_sha256(data[:80]))
    return {
        'version': version,
        'prev_block_hash': prev_hash,
        'merkle_root': merkle,
        'timestamp': timestamp,
        'bits': bits,
        'nonce': nonce,
        'block_hash': bhash,
    }


def compute_merkle_root(txids: List[str]) -> str:
    if not txids:
        return '00' * 32
    layer = [bytes.fromhex(t)[::-1] for t in txids]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [double_sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0][::-1].hex()


def decode_bip34_height(script_sig: bytes) -> Optional[int]:
    if not script_sig:
        return None
    length = script_sig[0]
    if length == 0 or length > len(script_sig) - 1:
        return None
    try:
        return int.from_bytes(script_sig[1:1 + length], 'little')
    except Exception:
        return None


def parse_block_file(blk_data: bytes, rev_data: bytes, network: str = 'mainnet') -> List[dict]:
    """Parse ALL blocks in a blk*.dat file. Returns list of block dicts."""
    undo_pool = _collect_undo_payloads(rev_data)
    undo_index: dict = defaultdict(list)
    for idx, payload in enumerate(undo_pool):
        try:
            undo_index[_read_compact_size_at(payload)].append(idx)
        except Exception:
            pass

    used_undos: set = set()
    results = []
    block_idx = 0

    for block_payload in _iter_frames(blk_data):
        try:
            result = _parse_single_block(
                block_payload, undo_pool, undo_index, used_undos, block_idx, network
            )
        except Exception as e:
            result = {
                'ok': False,
                'error': {'code': 'BLOCK_PARSE_ERROR', 'message': str(e)},
            }
        results.append(result)
        block_idx += 1

    return results


def _parse_single_block(block_payload: bytes, undo_pool, undo_index, used_undos, block_idx, network):
    if len(block_payload) < 81:
        raise ValueError("Block payload too short for header + varint")

    header = parse_block_header(block_payload)

    pos = 80
    first_byte = block_payload[pos]
    if first_byte < 0xfd:
        tx_count = first_byte; pos += 1
    elif first_byte == 0xfd:
        tx_count = struct.unpack_from('<H', block_payload, pos + 1)[0]; pos += 3
    elif first_byte == 0xfe:
        tx_count = struct.unpack_from('<I', block_payload, pos + 1)[0]; pos += 5
    else:
        tx_count = struct.unpack_from('<Q', block_payload, pos + 1)[0]; pos += 9

    block_mv = memoryview(block_payload)
    transactions = []
    for _ in range(tx_count):
        tx = parse_transaction(block_mv[pos:])
        pos += len(tx.raw_bytes)
        transactions.append(tx)

    expected_undo = tx_count - 1
    matched_idx: Optional[int] = None
    matched_results: Optional[list] = None

    def _try(idx: int) -> bool:
        nonlocal matched_idx, matched_results
        if idx in used_undos or not (0 <= idx < len(undo_pool)):
            return False
        try:
            if _read_compact_size_at(undo_pool[idx]) != expected_undo:
                return False
        except Exception:
            return False
        r = _parse_undo_payload(undo_pool[idx], transactions)
        if r is not None:
            matched_idx, matched_results = idx, r
            return True
        return False

    if not _try(block_idx):
        for ci in undo_index.get(expected_undo, []):
            if _try(ci):
                break

    if matched_results is None:
        if expected_undo == 0:
            matched_results, matched_idx = [], -1
        else:
            # Try all undo payloads as last resort
            found = False
            for i in range(len(undo_pool)):
                if _try(i):
                    found = True
                    break
            if not found:
                matched_results = []
                matched_idx = -1

    if matched_idx is not None and matched_idx >= 0:
        used_undos.add(matched_idx)

    for tx, tx_undo in zip(transactions[1:], matched_results or []):
        for inp, (value, script, height, is_cb) in zip(tx.inputs, tx_undo):
            inp.prevout_value = value
            inp.prevout_script = script
            inp.prevout_height = height
            inp.prevout_coinbase = is_cb

    txids = [compute_txid(tx) for tx in transactions]
    computed_merkle = compute_merkle_root(txids)
    merkle_valid = computed_merkle == header['merkle_root']

    coinbase_tx = transactions[0]
    coinbase_script = coinbase_tx.inputs[0].script_sig if coinbase_tx.inputs else b''
    bip34_height = decode_bip34_height(coinbase_script)
    total_cb_out = sum(o.value for o in coinbase_tx.outputs)

    tx_reports = []
    total_fees = 0
    total_weight = 0
    script_summary: dict = {}

    for i, tx in enumerate(transactions):
        txid = txids[i]
        size_bytes, weight, vbytes, _wb, _nwb = get_sizes(tx)
        total_weight += weight
        is_coinbase_tx = (i == 0)

        if is_coinbase_tx:
            fee = 0
        else:
            vin_sum = sum(inp.prevout_value for inp in tx.inputs)
            vout_sum = sum(o.value for o in tx.outputs)
            fee = max(vin_sum - vout_sum, 0)
            total_fees += fee

        vout_lite = []
        for o in tx.outputs:
            stype = classify_output_script(o.script_pubkey)
            script_summary[stype] = script_summary.get(stype, 0) + 1
            vout_lite.append({
                'n': o.n,
                'value_sats': o.value,
                'script_pubkey_hex': o.script_pubkey.hex(),
                'script_type': stype,
            })

        # Classify input script types using prevout scripts
        vin_lite = []
        for inp in tx.inputs:
            if is_coinbase_tx:
                in_type = 'coinbase'
            elif inp.prevout_script:
                in_type = classify_output_script(inp.prevout_script)
            else:
                in_type = 'unknown'
            vin_lite.append({
                'txid': inp.txid,
                'vout': inp.vout,
                'sequence': inp.sequence,
                'script_sig_hex': inp.script_sig.hex(),
                'witness': [w.hex() for w in inp.witness] if tx.segwit else [],
                'script_type': in_type,
                'prevout': {
                    'value_sats': inp.prevout_value,
                    'script_pubkey_hex': inp.prevout_script.hex() if inp.prevout_script else '',
                },
            })

        rbf = any(inp.sequence < 0xFFFFFFFE for inp in tx.inputs)

        tx_reports.append({
            'ok': True,
            'txid': txid,
            'version': tx.version,
            'locktime': tx.locktime,
            'segwit': tx.segwit,
            'size_bytes': size_bytes,
            'weight': weight,
            'vbytes': vbytes,
            'total_input_sats': 0 if is_coinbase_tx else sum(inp.prevout_value for inp in tx.inputs),
            'total_output_sats': sum(o.value for o in tx.outputs),
            'fee_sats': fee,
            'fee_rate_sat_vb': round(fee / vbytes, 4) if vbytes > 0 and fee > 0 else 0.0,
            'rbf_signaling': rbf,
            'vin': vin_lite,
            'vout': vout_lite,
            'is_coinbase': is_coinbase_tx,
        })

    avg_fee_rate = (
        round(total_fees / math.ceil(total_weight / 4), 4)
        if total_weight > 0 else 0.0
    )

    header['merkle_root_valid'] = merkle_valid

    return {
        'ok': True,
        'mode': 'block',
        'block_header': header,
        'tx_count': tx_count,
        'coinbase': {
            'bip34_height': bip34_height,
            'coinbase_script_hex': coinbase_script.hex(),
            'total_output_sats': total_cb_out,
        },
        'transactions': tx_reports,
        'block_stats': {
            'total_fees_sats': total_fees,
            'total_weight': total_weight,
            'avg_fee_rate_sat_vb': avg_fee_rate,
            'script_type_summary': script_summary,
        },
    }