# save as debug_rev.py and run from your project root
def xor_decode(data, key):
    if not key or all(b == 0 for b in key):
        return data
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def read_cvarint(data, pos):
    n = 0
    while True:
        b = data[pos]; pos += 1
        n = (n << 7) | (b & 0x7f)
        if b & 0x80: n += 1
        else: return n, pos

xor_key  = open('fixtures/blocks/xor.dat', 'rb').read()
rev_raw  = open('fixtures/blocks/rev04330.dat', 'rb').read()
blk_raw  = open('fixtures/blocks/blk04330.dat', 'rb').read()
rev_data = xor_decode(rev_raw, xor_key)
blk_data = xor_decode(blk_raw, xor_key)

# --- BLK: find first block's tx_count ---
assert blk_data[:4] == b'\xf9\xbe\xb4\xd9'
blk_size = int.from_bytes(blk_data[4:8], 'little')
blk_pay  = blk_data[8:8+blk_size]
b0 = blk_pay[80]
if b0 < 0xfd:
    blk_txcount = b0
elif b0 == 0xfd:
    blk_txcount = int.from_bytes(blk_pay[81:83], 'little')
print(f'BLK first block tx_count = {blk_txcount}')
print(f'Expected txundo_count    = {blk_txcount - 1}')
print()

# --- REV: show raw bytes at various offsets ---
assert rev_data[:4] == b'\xf9\xbe\xb4\xd9'
size = int.from_bytes(rev_data[4:8], 'little')
payload = rev_data[8:8+size]
print(f'REV block 0: size={size}, payload_len={len(payload)}')
print(f'First 40 bytes: {payload[:40].hex()}')
print()

# Try CVarInt at offset 0, 4, 8, 28, 32
for off in [0, 4, 8, 28, 32]:
    try:
        n, p = read_cvarint(payload, off)
        print(f'CVarInt@{off:2d} = {n:>12}  bytes_consumed={p-off}')
    except Exception as e:
        print(f'CVarInt@{off:2d} = ERROR {e}')

print()
# Try CompactSize at offset 0
b = payload[0]
if b < 0xfd:
    print(f'CompactSize@0 = {b}')
elif b == 0xfd:
    print(f'CompactSize@0 (fd) = {int.from_bytes(payload[1:3], "little")}')
elif b == 0xfe:
    print(f'CompactSize@0 (fe) = {int.from_bytes(payload[1:5], "little")}')