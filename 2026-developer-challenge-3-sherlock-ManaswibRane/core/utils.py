import hashlib
import struct
from typing import Optional


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def double_sha256(data) -> bytes:
    return sha256(sha256(bytes(data) if isinstance(data, memoryview) else data))


def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', sha256(data)).digest()


def to_little_endian_hex(b) -> str:
    return bytes(b)[::-1].hex()


def encode_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


class ByteReader:
    __slots__ = ('_mv', 'pos')

    def __init__(self, data):
        self._mv = data if isinstance(data, memoryview) else memoryview(data)
        self.pos = 0

    @property
    def _data(self):
        return self._mv

    def read(self, n: int) -> bytes:
        end = self.pos + n
        if end > len(self._mv):
            raise ValueError(f"Not enough bytes: need {n}, have {len(self._mv) - self.pos} at pos {self.pos}")
        result = bytes(self._mv[self.pos:end])
        self.pos = end
        return result

    def read_varint(self) -> int:
        pos = self.pos
        first = self._mv[pos]
        pos += 1
        if first < 0xfd:
            self.pos = pos
            return first
        if first == 0xfd:
            val = struct.unpack_from('<H', self._mv, pos)[0]
            self.pos = pos + 2
            return val
        if first == 0xfe:
            val = struct.unpack_from('<I', self._mv, pos)[0]
            self.pos = pos + 4
            return val
        val = struct.unpack_from('<Q', self._mv, pos)[0]
        self.pos = pos + 8
        return val

    def read_uint32(self) -> int:
        val = struct.unpack_from('<I', self._mv, self.pos)[0]
        self.pos += 4
        return val

    def read_int32(self) -> int:
        val = struct.unpack_from('<i', self._mv, self.pos)[0]
        self.pos += 4
        return val

    def read_uint64(self) -> int:
        val = struct.unpack_from('<Q', self._mv, self.pos)[0]
        self.pos += 8
        return val

    def peek(self, n: int = 1) -> bytes:
        return bytes(self._mv[self.pos:self.pos + n])

    def remaining(self) -> int:
        return len(self._mv) - self.pos

    def tell(self) -> int:
        return self.pos