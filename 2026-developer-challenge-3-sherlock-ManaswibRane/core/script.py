import struct
from typing import Optional

OPCODES = {
    0x00: 'OP_0', 0x4f: 'OP_1NEGATE',
    0x51: 'OP_1', 0x52: 'OP_2', 0x53: 'OP_3', 0x54: 'OP_4',
    0x55: 'OP_5', 0x56: 'OP_6', 0x57: 'OP_7', 0x58: 'OP_8',
    0x59: 'OP_9', 0x5a: 'OP_10', 0x5b: 'OP_11', 0x5c: 'OP_12',
    0x5d: 'OP_13', 0x5e: 'OP_14', 0x5f: 'OP_15', 0x60: 'OP_16',
    0x61: 'OP_NOP', 0x63: 'OP_IF', 0x64: 'OP_NOTIF',
    0x67: 'OP_ELSE', 0x68: 'OP_ENDIF',
    0x69: 'OP_VERIFY', 0x6a: 'OP_RETURN',
    0x76: 'OP_DUP', 0x87: 'OP_EQUAL', 0x88: 'OP_EQUALVERIFY',
    0xa9: 'OP_HASH160', 0xac: 'OP_CHECKSIG', 0xae: 'OP_CHECKMULTISIG',
    0xba: 'OP_CHECKSIGADD',
}


def classify_output_script(script: bytes) -> str:
    if isinstance(script, (bytearray, memoryview)):
        script = bytes(script)
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


def decode_op_return(script: bytes):
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
    elif data_hex.startswith('52554e45') or data_hex.startswith('6a5d'):
        protocol = 'runes'
    elif b'ord' in data[:10]:
        protocol = 'ordinals'
    return data_hex, data_utf8, protocol