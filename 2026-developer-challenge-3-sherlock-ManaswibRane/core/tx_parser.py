import struct
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional
from core.utils import ByteReader, double_sha256, to_little_endian_hex, encode_varint


@dataclass
class TxInput:
    txid: str = ''
    vout: int = 0
    script_sig: bytes = b''
    sequence: int = 0xffffffff
    witness: List[bytes] = field(default_factory=list)
    prevout_value: int = 0
    prevout_script: bytes = b''
    prevout_height: int = 0
    prevout_coinbase: bool = False


@dataclass
class TxOutput:
    n: int = 0
    value: int = 0
    script_pubkey: bytes = b''


@dataclass
class Transaction:
    version: int = 1
    locktime: int = 0
    inputs: List[TxInput] = field(default_factory=list)
    outputs: List[TxOutput] = field(default_factory=list)
    segwit: bool = False
    raw_bytes: bytes = b''
    non_witness_bytes: bytes = b''
    witness_bytes_total: int = 0


def parse_transaction(data) -> Transaction:
    if isinstance(data, (bytes, bytearray)):
        mv = memoryview(bytes(data))
    elif isinstance(data, memoryview):
        mv = data
    else:
        mv = memoryview(bytes(data))

    r = ByteReader(mv)
    start = r.pos

    version = r.read_int32()
    
    # Check for segwit marker
    segwit = False
    peek = r.peek(2)
    if len(peek) >= 2 and peek[0] == 0x00 and peek[1] == 0x01:
        segwit = True
        r.read(2)  # consume marker + flag

    # Inputs
    in_count = r.read_varint()
    inputs = []
    for _ in range(in_count):
        txid_raw = r.read(32)
        txid = bytes(txid_raw)[::-1].hex()
        vout = r.read_uint32()
        script_len = r.read_varint()
        script_sig = r.read(script_len)
        sequence = r.read_uint32()
        inputs.append(TxInput(txid=txid, vout=vout, script_sig=script_sig, sequence=sequence))

    # Outputs
    out_count = r.read_varint()
    outputs = []
    for i in range(out_count):
        value = r.read_uint64()
        script_len = r.read_varint()
        script_pubkey = r.read(script_len)
        outputs.append(TxOutput(n=i, value=value, script_pubkey=script_pubkey))

    # Witnesses
    witness_start = r.pos
    if segwit:
        for inp in inputs:
            wit_count = r.read_varint()
            for _ in range(wit_count):
                item_len = r.read_varint()
                item = r.read(item_len)
                inp.witness.append(item)
    witness_end = r.pos

    locktime = r.read_uint32()
    end = r.pos

    raw = bytes(mv[start:end])

    # Build non-witness serialization for txid
    nw = struct.pack('<i', version)
    nw += encode_varint(in_count)
    for inp in inputs:
        nw += bytes.fromhex(inp.txid)[::-1]
        nw += struct.pack('<I', inp.vout)
        nw += encode_varint(len(inp.script_sig)) + inp.script_sig
        nw += struct.pack('<I', inp.sequence)
    nw += encode_varint(out_count)
    for out in outputs:
        nw += struct.pack('<Q', out.value)
        nw += encode_varint(len(out.script_pubkey)) + out.script_pubkey
    nw += struct.pack('<I', locktime)

    tx = Transaction(
        version=version,
        locktime=locktime,
        inputs=inputs,
        outputs=outputs,
        segwit=segwit,
        raw_bytes=raw,
        non_witness_bytes=nw,
        witness_bytes_total=witness_end - witness_start,
    )
    return tx


def compute_txid(tx: Transaction) -> str:
    h = double_sha256(tx.non_witness_bytes)
    return h[::-1].hex()


def get_sizes(tx: Transaction):
    size_bytes = len(tx.raw_bytes)
    non_witness_size = len(tx.non_witness_bytes)
    witness_size = tx.witness_bytes_total

    # Weight = non_witness * 4 + witness * 1
    # But segwit marker/flag = 2 bytes counted as witness
    if tx.segwit:
        # raw = non_witness_part + 2(marker/flag) + witnesses + locktime
        # Actually: weight = base_size * 3 + total_size
        base_size = non_witness_size
        total_size = size_bytes
        weight = base_size * 3 + total_size
    else:
        weight = size_bytes * 4

    vbytes = (weight + 3) // 4
    return size_bytes, weight, vbytes, witness_size, non_witness_size