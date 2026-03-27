import math
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Union
from core.utils import ByteReader, double_sha256, to_little_endian_hex, encode_varint


@dataclass
class TxInput:
    txid: str
    vout: int
    script_sig: bytes
    sequence: int
    witness: List[bytes] = field(default_factory=list)
    prevout_value: int = 0
    prevout_script: bytes = b''
    # Raw txid bytes (little-endian, wire order) — avoids bytes.fromhex()[::-1]
    # round-trip in _build_non_witness.
    _txid_raw: bytes = field(default=b'', repr=False)
    prevout_height: int = 0
    prevout_coinbase: bool = False


@dataclass
class TxOutput:
    n: int
    value: int
    script_pubkey: bytes


@dataclass
class Transaction:
    version: int
    inputs: List[TxInput]
    outputs: List[TxOutput]
    locktime: int
    segwit: bool
    raw_bytes: bytes = b''
    non_witness_bytes: bytes = b''


# Fix 1: accept memoryview directly — no bytes() copy at the call site.
# ByteReader already stores data as memoryview internally, so passing a
# memoryview slice from block_mv[pos:] is entirely zero-copy until we
# explicitly call .read() which makes a bytes copy only for the slice needed.
def parse_transaction(raw) -> Transaction:
    """
    Parse a transaction from bytes, bytearray, or memoryview.

    FIX 1: Caller (block_parser) now passes block_mv[pos:] directly
    (a memoryview slice, O(1) to create) instead of bytes(block_mv[pos:])
    (an O(n) copy of the rest of the block).  Over 500 k transactions in a
    128 MB file, eliminating that copy saves gigabytes of allocations.

    raw_bytes is stored as bytes (not memoryview) so that it can be hashed
    and kept alive independently of the original block buffer.
    """
    reader = ByteReader(raw)
    start  = reader.pos
    version = reader.read_int32()

    segwit = False
    if reader.peek(2) == b'\x00\x01':
        reader.read(2)
        segwit = True

    in_count = reader.read_varint()
    inputs = []
    for _ in range(in_count):
        txid_raw = reader.read(32)          # bytes (little-endian wire order)
        txid     = txid_raw[::-1].hex()     # display hex (big-endian)
        vout     = reader.read_uint32()
        script_len = reader.read_varint()
        script_sig = reader.read(script_len)
        sequence   = reader.read_uint32()
        inputs.append(TxInput(
            txid=txid, vout=vout, script_sig=script_sig,
            sequence=sequence, _txid_raw=txid_raw,
        ))

    out_count = reader.read_varint()
    outputs = []
    for n in range(out_count):
        value      = reader.read_uint64()
        script_len = reader.read_varint()
        script_pubkey = reader.read(script_len)
        outputs.append(TxOutput(n=n, value=value, script_pubkey=script_pubkey))

    if segwit:
        for inp in inputs:
            wit_count = reader.read_varint()
            for _ in range(wit_count):
                item_len = reader.read_varint()
                inp.witness.append(reader.read(item_len))

    locktime = reader.read_uint32()
    end      = reader.pos

    # raw_bytes: bytes copy of exactly this transaction (needed for wtxid hash
    # and to record consumed length).  We copy only the transaction slice,
    # not the remainder of the block.
    raw_bytes = bytes(reader._mv[start:end])

    non_witness = _build_non_witness(version, inputs, outputs, locktime)

    return Transaction(
        version=version, inputs=inputs, outputs=outputs,
        locktime=locktime, segwit=segwit,
        raw_bytes=raw_bytes, non_witness_bytes=non_witness,
    )


def _build_non_witness(version, inputs, outputs, locktime) -> bytes:
    """
    Serialise the non-witness form used for TXID hashing.

    Pre-allocates a single bytearray of the exact final size, then fills
    it in-place with struct.pack_into — O(n) instead of the O(n²) bytes
    concatenation in the original code.

    Uses _txid_raw (cached wire-order bytes) to avoid the
    bytes.fromhex(inp.txid)[::-1] round-trip.
    """
    size = 4  # version
    size += _varint_size(len(inputs))
    for inp in inputs:
        size += 32 + 4
        size += _varint_size(len(inp.script_sig)) + len(inp.script_sig)
        size += 4
    size += _varint_size(len(outputs))
    for o in outputs:
        size += 8
        size += _varint_size(len(o.script_pubkey)) + len(o.script_pubkey)
    size += 4

    buf = bytearray(size)
    pos = 0

    struct.pack_into('<i', buf, pos, version);  pos += 4
    pos = _write_varint(buf, pos, len(inputs))
    for inp in inputs:
        raw = inp._txid_raw if inp._txid_raw else bytes.fromhex(inp.txid)[::-1]
        buf[pos:pos + 32] = raw;                        pos += 32
        struct.pack_into('<I', buf, pos, inp.vout);     pos += 4
        pos = _write_varint(buf, pos, len(inp.script_sig))
        n = len(inp.script_sig)
        buf[pos:pos + n] = inp.script_sig;              pos += n
        struct.pack_into('<I', buf, pos, inp.sequence); pos += 4

    pos = _write_varint(buf, pos, len(outputs))
    for o in outputs:
        struct.pack_into('<Q', buf, pos, o.value);      pos += 8
        pos = _write_varint(buf, pos, len(o.script_pubkey))
        n = len(o.script_pubkey)
        buf[pos:pos + n] = o.script_pubkey;             pos += n

    struct.pack_into('<I', buf, pos, locktime)
    return bytes(buf)


# ── Inline varint helpers (avoid encode_varint() call + allocation) ───────────

def _varint_size(n: int) -> int:
    if n < 0xfd:          return 1
    if n <= 0xffff:       return 3
    if n <= 0xffffffff:   return 5
    return 9


def _write_varint(buf: bytearray, pos: int, n: int) -> int:
    if n < 0xfd:
        buf[pos] = n;                                          return pos + 1
    if n <= 0xffff:
        buf[pos] = 0xfd; struct.pack_into('<H', buf, pos+1, n); return pos + 3
    if n <= 0xffffffff:
        buf[pos] = 0xfe; struct.pack_into('<I', buf, pos+1, n); return pos + 5
    buf[pos] = 0xff;     struct.pack_into('<Q', buf, pos+1, n); return pos + 9


def compute_txid(tx: Transaction) -> str:
    return to_little_endian_hex(double_sha256(tx.non_witness_bytes))


def compute_wtxid(tx: Transaction) -> Optional[str]:
    if not tx.segwit:
        return None
    return to_little_endian_hex(double_sha256(tx.raw_bytes))


def get_sizes(tx: Transaction):
    """Returns (size_bytes, weight, vbytes, witness_bytes, non_witness_bytes)"""
    if not tx.segwit:
        size = len(tx.non_witness_bytes)
        return size, size * 4, size, 0, size

    witness_bytes = 2  # marker + flag
    for inp in tx.inputs:
        witness_bytes += _varint_size(len(inp.witness))
        for item in inp.witness:
            witness_bytes += _varint_size(len(item)) + len(item)

    non_witness_size = len(tx.non_witness_bytes)
    total_size = non_witness_size + witness_bytes
    weight     = non_witness_size * 4 + witness_bytes
    vbytes     = math.ceil(weight / 4)
    return total_size, weight, vbytes, witness_bytes, non_witness_size