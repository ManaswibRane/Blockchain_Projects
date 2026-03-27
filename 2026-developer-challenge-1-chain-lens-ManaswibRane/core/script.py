import hashlib
import struct
from typing import Optional

BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

OPCODES = {
    0x00: 'OP_0',
    0x4f: 'OP_1NEGATE',
    0x51: 'OP_1', 0x52: 'OP_2', 0x53: 'OP_3', 0x54: 'OP_4',
    0x55: 'OP_5', 0x56: 'OP_6', 0x57: 'OP_7', 0x58: 'OP_8',
    0x59: 'OP_9', 0x5a: 'OP_10', 0x5b: 'OP_11', 0x5c: 'OP_12',
    0x5d: 'OP_13', 0x5e: 'OP_14', 0x5f: 'OP_15', 0x60: 'OP_16',
    0x61: 'OP_NOP',
    0x63: 'OP_IF', 0x64: 'OP_NOTIF',
    0x67: 'OP_ELSE', 0x68: 'OP_ENDIF',
    0x69: 'OP_VERIFY', 0x6a: 'OP_RETURN',
    0x6b: 'OP_TOALTSTACK', 0x6c: 'OP_FROMALTSTACK',
    0x6d: 'OP_2DROP', 0x6e: 'OP_2DUP', 0x6f: 'OP_3DUP',
    0x70: 'OP_2OVER', 0x71: 'OP_2ROT', 0x72: 'OP_2SWAP',
    0x73: 'OP_IFDUP', 0x74: 'OP_DEPTH', 0x75: 'OP_DROP',
    0x76: 'OP_DUP',
    0x77: 'OP_NIP', 0x78: 'OP_OVER',
    0x79: 'OP_PICK', 0x7a: 'OP_ROLL', 0x7b: 'OP_ROT',
    0x7c: 'OP_SWAP', 0x7d: 'OP_TUCK',
    0x7e: 'OP_CAT', 0x7f: 'OP_SUBSTR', 0x80: 'OP_LEFT', 0x81: 'OP_RIGHT',
    0x82: 'OP_SIZE',
    0x83: 'OP_INVERT', 0x84: 'OP_AND', 0x85: 'OP_OR', 0x86: 'OP_XOR',
    0x87: 'OP_EQUAL', 0x88: 'OP_EQUALVERIFY',
    0x8b: 'OP_1ADD', 0x8c: 'OP_1SUB',
    0x8f: 'OP_NEGATE', 0x90: 'OP_ABS', 0x91: 'OP_NOT', 0x92: 'OP_0NOTEQUAL',
    0x93: 'OP_ADD', 0x94: 'OP_SUB',
    0x9a: 'OP_BOOLAND', 0x9b: 'OP_BOOLOR',
    0x9c: 'OP_NUMEQUAL', 0x9d: 'OP_NUMEQUALVERIFY', 0x9e: 'OP_NUMNOTEQUAL',
    0x9f: 'OP_LESSTHAN', 0xa0: 'OP_GREATERTHAN',
    0xa1: 'OP_LESSTHANOREQUAL', 0xa2: 'OP_GREATERTHANOREQUAL',
    0xa3: 'OP_MIN', 0xa4: 'OP_MAX', 0xa5: 'OP_WITHIN',
    0xa6: 'OP_RIPEMD160', 0xa7: 'OP_SHA1', 0xa8: 'OP_SHA256',
    0xa9: 'OP_HASH160', 0xaa: 'OP_HASH256',
    0xab: 'OP_CODESEPARATOR',
    0xac: 'OP_CHECKSIG', 0xad: 'OP_CHECKSIGVERIFY',
    0xae: 'OP_CHECKMULTISIG', 0xaf: 'OP_CHECKMULTISIGVERIFY',
    0xb0: 'OP_NOP1',
    0xb1: 'OP_CHECKLOCKTIMEVERIFY',
    0xb2: 'OP_CHECKSEQUENCEVERIFY',
    0xb3: 'OP_NOP4', 0xb4: 'OP_NOP5', 0xb5: 'OP_NOP6',
    0xb6: 'OP_NOP7', 0xb7: 'OP_NOP8', 0xb8: 'OP_NOP9', 0xb9: 'OP_NOP10',
    0xba: 'OP_CHECKSIGADD',
}


def disassemble_script(script_bytes: bytes) -> str:
    if not script_bytes:
        return ""
    tokens = []
    i = 0
    while i < len(script_bytes):
        op = script_bytes[i]
        i += 1
        if op == 0x00:
            tokens.append('OP_0')
        elif 0x01 <= op <= 0x4b:
            data = script_bytes[i:i + op]
            i += op
            tokens.append(f'OP_PUSHBYTES_{op} {data.hex()}')
        elif op == 0x4c:
            length = script_bytes[i]; i += 1
            data = script_bytes[i:i + length]; i += length
            tokens.append(f'OP_PUSHDATA1 {data.hex()}')
        elif op == 0x4d:
            length = struct.unpack('<H', script_bytes[i:i + 2])[0]; i += 2
            data = script_bytes[i:i + length]; i += length
            tokens.append(f'OP_PUSHDATA2 {data.hex()}')
        elif op == 0x4e:
            length = struct.unpack('<I', script_bytes[i:i + 4])[0]; i += 4
            data = script_bytes[i:i + length]; i += length
            tokens.append(f'OP_PUSHDATA4 {data.hex()}')
        elif op in OPCODES:
            tokens.append(OPCODES[op])
        else:
            tokens.append(f'OP_UNKNOWN_{hex(op)}')
    return ' '.join(tokens)


def classify_output_script(script: bytes) -> str:
    n = len(script)
    if n == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac:
        return 'p2pkh'
    if n == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87:
        return 'p2sh'
    if n == 22 and script[0] == 0x00 and script[1] == 0x14:
        return 'p2wpkh'
    if n == 34 and script[0] == 0x00 and script[1] == 0x20:
        return 'p2wsh'
    if n == 34 and script[0] == 0x51 and script[1] == 0x20:
        return 'p2tr'
    if n >= 1 and script[0] == 0x6a:
        return 'op_return'
    return 'unknown'


def classify_input_script(script_sig: bytes, witness: list, prevout_script: bytes) -> str:
    """
    Classify input spend type.

    Valid return values per spec:
      p2pkh, p2sh-p2wpkh, p2sh-p2wsh, p2wpkh, p2wsh,
      p2tr_keypath, p2tr_scriptpath, unknown

    Note: plain 'p2sh' is NOT a valid input script_type per spec.
    A P2SH input that doesn't wrap a recognised SegWit script returns 'unknown'.

    witness items may be passed as either List[bytes] or List[str] (hex).
    We normalise to bytes internally.
    """
    def _to_bytes(item):
        if isinstance(item, (bytes, bytearray)):
            return bytes(item)
        return bytes.fromhex(item) if item else b''

    prevout_type = classify_output_script(prevout_script)

    if prevout_type == 'p2wpkh':
        return 'p2wpkh'

    if prevout_type == 'p2wsh':
        return 'p2wsh'

    if prevout_type == 'p2tr':
        if not witness:
            return 'p2tr_keypath'
        items = [_to_bytes(w) for w in witness]
        # Strip annex if present (last item starts with 0x50 and ≥2 items)
        if len(items) >= 2 and items[-1][:1] == b'\x50':
            items = items[:-1]
        # Keypath: exactly 1 item (64- or 65-byte Schnorr sig)
        if len(items) == 1:
            return 'p2tr_keypath'
        return 'p2tr_scriptpath'

    if prevout_type == 'p2pkh':
        return 'p2pkh'

    if prevout_type == 'p2sh':
        # Check whether this is a nested-SegWit spend by inspecting the
        # last push in scriptSig (the serialised redeem script).
        if script_sig:
            redeem = _last_push(script_sig)
            if redeem:
                rt = classify_output_script(redeem)
                if rt == 'p2wpkh':
                    return 'p2sh-p2wpkh'
                if rt == 'p2wsh':
                    return 'p2sh-p2wsh'
        # Plain P2SH spend (bare multisig, custom script, etc.).
        # 'p2sh' is not a valid input script_type per the spec — use 'unknown'.
        return 'unknown'

    return 'unknown'


def _last_push(script: bytes) -> Optional[bytes]:
    """Return the data from the last push opcode in script, or None."""
    result = None
    i = 0
    while i < len(script):
        op = script[i]; i += 1
        if 0x01 <= op <= 0x4b:
            result = script[i:i + op]; i += op
        elif op == 0x4c:
            if i >= len(script): break
            l = script[i]; i += 1; result = script[i:i + l]; i += l
        elif op == 0x4d:
            if i + 2 > len(script): break
            l = struct.unpack('<H', script[i:i + 2])[0]; i += 2; result = script[i:i + l]; i += l
        elif op == 0x4e:
            if i + 4 > len(script): break
            l = struct.unpack('<I', script[i:i + 4])[0]; i += 4; result = script[i:i + l]; i += l
        else:
            i += 0  # non-push opcode
    return result


def decode_op_return(script: bytes):
    """
    Parse OP_RETURN payload. Handles all push opcodes including
    OP_PUSHDATA1/2/4 and multiple concatenated pushes.

    Returns (data_hex, data_utf8_or_None, protocol_str).
    """
    if not script or script[0] != 0x6a:
        return "", None, "unknown"
    i = 1
    parts = []
    while i < len(script):
        op = script[i]; i += 1
        if 0x01 <= op <= 0x4b:
            parts.append(script[i:i + op]); i += op
        elif op == 0x4c:
            if i >= len(script): break
            l = script[i]; i += 1; parts.append(script[i:i + l]); i += l
        elif op == 0x4d:
            if i + 2 > len(script): break
            l = struct.unpack('<H', script[i:i + 2])[0]; i += 2; parts.append(script[i:i + l]); i += l
        elif op == 0x4e:
            if i + 4 > len(script): break
            l = struct.unpack('<I', script[i:i + 4])[0]; i += 4; parts.append(script[i:i + l]); i += l
        elif op == 0x00:
            parts.append(b'')
        # Other opcodes after OP_RETURN are ignored
    data = b''.join(parts)
    data_hex = data.hex()
    try:
        data_utf8 = data.decode('utf-8')
    except Exception:
        data_utf8 = None
    protocol = 'unknown'
    if data_hex.startswith('6f6d6e69'):
        protocol = 'omni'
    elif data_hex.startswith('0109f91102'):
        protocol = 'opentimestamps'
    return data_hex, data_utf8, protocol


# ── Address derivation ────────────────────────────────────────────────────────

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash160_fn(data: bytes) -> bytes:
    return hashlib.new('ripemd160', _sha256(data)).digest()


def base58check_encode(payload: bytes) -> str:
    checksum = _sha256(_sha256(payload))[:4]
    data = payload + checksum
    count = 0
    for b in data:
        if b == 0:
            count += 1
        else:
            break
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(BASE58_ALPHABET[r:r + 1])
    result.reverse()
    return (b'1' * count + b''.join(result)).decode('ascii')


def _bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_encode(hrp: str, data: list, spec: str = 'bech32') -> str:
    const = 1 if spec == 'bech32' else 0x2bc830a3
    combined = data + [0, 0, 0, 0, 0, 0]
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + combined) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + '1' + ''.join([BECH32_CHARSET[d] for d in data + checksum])


def _convertbits(data, frombits: int, tobits: int, pad: bool = True):
    acc = 0; bits = 0; ret = []; maxv = (1 << tobits) - 1
    for value in data:
        acc = ((acc << frombits) | value) & 0xffffffff
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def script_to_address(script: bytes, network: str = 'mainnet') -> Optional[str]:
    if not script:
        return None
    stype = classify_output_script(script)
    hrp = 'bc' if network == 'mainnet' else 'tb'
    p2pkh_ver = b'\x00' if network == 'mainnet' else b'\x6f'
    p2sh_ver  = b'\x05' if network == 'mainnet' else b'\xc4'

    if stype == 'p2pkh':
        return base58check_encode(p2pkh_ver + script[3:23])
    if stype == 'p2sh':
        return base58check_encode(p2sh_ver + script[2:22])
    if stype == 'p2wpkh':
        data = _convertbits(script[2:22], 8, 5)
        return _bech32_encode(hrp, [0] + data, spec='bech32')
    if stype == 'p2wsh':
        data = _convertbits(script[2:34], 8, 5)
        return _bech32_encode(hrp, [0] + data, spec='bech32')
    if stype == 'p2tr':
        data = _convertbits(script[2:34], 8, 5)
        return _bech32_encode(hrp, [1] + data, spec='bech32m')
    return None