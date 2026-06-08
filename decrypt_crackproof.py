import struct
import os
import sys

# ============================================================
# CrackProof Shell Unpacker (DLL + EXE)
# Auto-locate offsets, 8-stage decryption chain
# ============================================================

# ---------- helpers ----------
def u8(data, off):
    return data[off]

def u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def w8(data, off, val):
    data[off] = val & 0xFF

def w16(data, off, val):
    struct.pack_into('<H', data, off, val & 0xFFFF)

def w32(data, off, val):
    struct.pack_into('<I', data, off, val & 0xFFFFFFFF)

def bswap32(v):
    return struct.unpack('>I', struct.pack('<I', v & 0xFFFFFFFF))[0]

def ror8(b, n):
    n &= 7
    return ((b >> n) | (b << (8 - n))) & 0xFF

def rol8(b, n):
    n &= 7
    return ((b << n) | (b >> (8 - n))) & 0xFF

# ---------- CRC32 (same as Force.Crc32) ----------
_crc_table = None
def _init_crc():
    global _crc_table
    if _crc_table is not None:
        return
    _crc_table = []
    for i in range(256):
        c = i
        for _ in range(8):
            if c & 1:
                c = 0xEDB88320 ^ (c >> 1)
            else:
                c >>= 1
        _crc_table.append(c & 0xFFFFFFFF)

def crc32(data, offset, size, init=0):
    _init_crc()
    crc = init ^ 0xFFFFFFFF
    for i in range(size):
        crc = _crc_table[(crc ^ data[offset + i]) & 0xFF] ^ (crc >> 8)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF

def checksum_with_size_xor(data, addr):
    off = u32(data, addr)
    sz = u32(data, addr + 4)
    return crc32(data, off, sz) ^ sz

def checksum_append(data, addr, start):
    off = u32(data, addr)
    sz = u32(data, addr + 4)
    return crc32(data, off, sz, init=(start ^ 0xFFFFFFFF) ^ 0xFFFFFFFF)

# ---------- DecryptData1: info extraction ----------
def decrypt_data1(file_data):
    base = 4096
    info = [0] * 8
    tmp = u32(file_data, base)
    info[0] = tmp
    for i in range(7):
        val = u32(file_data, base + (i + 1) * 4)
        info[i + 1] = (tmp ^ val) & 0xFFFFFFFF
        tmp = ((i * i) ^ ((tmp + val) & 0xFFFFFFFF) - i) & 0xFFFFFFFF
    return info

# ---------- DecryptData2: shell region ----------
def decrypt_data2(file_data, data, info, decrypt_size):
    offset = info[4] + 4096
    tmp = (info[0] + (~decrypt_size & 0xFFFFFFFF)) & 0xFFFFFFFF
    count = decrypt_size >> 2
    for i in range(count):
        idx = i * 4
        d_off = offset + idx
        w_off = info[3] + idx
        val = u32(file_data, d_off)
        w32(data, w_off, tmp ^ val)
        tmp = ((i * i) ^ ((tmp + val + i) & 0xFFFFFFFF)) & 0xFFFFFFFF

# ---------- DecryptData3: XOR + rotate ----------
def decrypt_data3(data, data_offset, key, shift):
    off = u32(data, data_offset)
    sz = u32(data, data_offset + 4)
    rev = 32 - shift
    count = sz >> 2
    for i in range(count):
        addr = off + i * 4
        val = u32(data, addr) ^ key
        key = (key + i) & 0xFFFFFFFF
        val = (((val >> shift) | (val << rev)) & 0xFFFFFFFF)
        val = (val - i) & 0xFFFFFFFF
        w32(data, addr, val)

# ---------- DecryptData4: byte rotate(5) + xor ----------
def decrypt_data4(data, data_offset):
    va = u32(data, data_offset)
    sz = u32(data, data_offset + 4)
    key1 = ((va >> 8) + va) & 0xFF
    key2 = (key1 + 1) & 0xFF
    for i in range(sz):
        addr = va + i
        b = data[addr]
        b = ror8(b, 5) ^ key2
        b = ror8(b, 5) ^ key1
        b = ror8(b, 5)
        data[addr] = b
        key1 = (key1 + 1) & 0xFF
        key2 = (key2 + 1) & 0xFF

# ---------- DecryptData5: byte rotate(6) + xor ----------
def decrypt_data5(data, va, size):
    key1 = va & 0xFF
    key2 = (key1 + 1) & 0xFF
    for i in range(size):
        addr = va + i
        b = data[addr]
        b = ror8(b, 6) ^ key2
        b = ror8(b, 6) ^ key1
        b = ror8(b, 6)
        data[addr] = b
        key1 = (key1 + 1) & 0xFF
        key2 = (key2 + 1) & 0xFF

# ---------- DecryptData6: LFSR ----------
def decrypt_data6(data, data_offset):
    sz = data[data_offset + 95]
    lfsr = 1
    for i in range(sz):
        addr = data_offset + i
        b = data[addr]
        for bit in range(8):
            fb = lfsr & 1
            b ^= (fb << bit)
            lfsr <<= 1
            if lfsr & 0x8000:
                lfsr ^= 0x8003
            lfsr &= 0xFFFF
        data[addr] = b & 0xFF

# ---------- DecryptData7: nibble swap + sub ----------
def decrypt_data7(data, data_offset, key):
    idx = 0
    while data[data_offset + idx] != 0:
        addr = data_offset + idx
        b = data[addr]
        b = ((b << 4) | (b >> 4)) & 0xFF
        b = (b - key) & 0xFF
        if b == 0:
            b = (-key) & 0xFF
        data[addr] = b
        key = (key + 67) & 0xFF
        idx += 1

# ---------- DecryptData8: rotated index xor ----------
def decrypt_data8(data, data_offset, size, key):
    count = size >> 4
    for i in range(count):
        rk = ((key >> 15) | (key << 17)) & 0xFFFFFFFF
        ri = (rk + i) & 0xFFFFFFFF
        key = (ri + i) & 0xFFFFFFFF
        tidx = data_offset + i * 16 + (ri & 0xF)
        data[tidx] = (data[tidx] ^ key) & 0xFF


# ============================================================
# AES Decrypt (custom implementation with external tables)
# ============================================================

colum_mix1 = None
colum_mix2 = None
colum_mix3 = None
colum_mix4 = None
aes_sbox = None

def load_aes_tables(base_dir):
    global colum_mix1, colum_mix2, colum_mix3, colum_mix4, aes_sbox
    colum_mix1 = bytearray(open(os.path.join(base_dir, 'aes_colum_mix1'), 'rb').read())
    colum_mix2 = bytearray(open(os.path.join(base_dir, 'aes_colum_mix2'), 'rb').read())
    colum_mix3 = bytearray(open(os.path.join(base_dir, 'aes_colum_mix3'), 'rb').read())
    colum_mix4 = bytearray(open(os.path.join(base_dir, 'aes_colum_mix4'), 'rb').read())
    aes_sbox   = bytearray(open(os.path.join(base_dir, 'aes_sbox'), 'rb').read())

def tbl32(tbl, idx):
    return struct.unpack_from('<I', tbl, idx * 4)[0]

def aes_round(data, data_off, key_off, rounds):
    state = [0] * 4
    temp = [0] * 4
    for i in range(4):
        state[i] = bswap32(u32(data, data_off + i * 4)) ^ u32(data, key_off + i * 4)
    for r in range(1, rounds):
        ki = key_off + r * 16
        temp[0] = tbl32(colum_mix2, (state[3] >> 16) & 0xFF) ^                   tbl32(colum_mix3, (state[2] >> 8) & 0xFF) ^                   tbl32(colum_mix1, (state[0] >> 24) & 0xFF) ^                   tbl32(colum_mix4, state[1] & 0xFF) ^ u32(data, ki)
        temp[1] = tbl32(colum_mix2, (state[0] >> 16) & 0xFF) ^                   tbl32(colum_mix1, (state[1] >> 24) & 0xFF) ^                   tbl32(colum_mix3, (state[3] >> 8) & 0xFF) ^                   tbl32(colum_mix4, state[2] & 0xFF) ^ u32(data, ki + 4)
        temp[2] = tbl32(colum_mix2, (state[1] >> 16) & 0xFF) ^                   tbl32(colum_mix3, (state[0] >> 8) & 0xFF) ^                   tbl32(colum_mix1, (state[2] >> 24) & 0xFF) ^                   tbl32(colum_mix4, state[3] & 0xFF) ^ u32(data, ki + 8)
        temp[3] = tbl32(colum_mix3, (state[1] >> 8) & 0xFF) ^                   tbl32(colum_mix2, (state[2] >> 16) & 0xFF) ^                   tbl32(colum_mix1, (state[3] >> 24) & 0xFF) ^                   tbl32(colum_mix4, state[0] & 0xFF) ^ u32(data, ki + 12)
        state = temp[:]
    fki = key_off + rounds * 16
    fs = [0] * 4
    fs[0] = ((tbl32(aes_sbox, (state[0] >> 24) & 0xFF) & 0xFF000000) |
             (tbl32(aes_sbox, (state[3] >> 16) & 0xFF) & 0x00FF0000) |
             (tbl32(aes_sbox, (state[2] >> 8) & 0xFF) & 0x0000FF00) |
             (tbl32(aes_sbox, state[1] & 0xFF) & 0x000000FF)) ^ u32(data, fki)
    fs[1] = ((tbl32(aes_sbox, (state[1] >> 24) & 0xFF) & 0xFF000000) |
             (tbl32(aes_sbox, (state[0] >> 16) & 0xFF) & 0x00FF0000) |
             (tbl32(aes_sbox, (state[3] >> 8) & 0xFF) & 0x0000FF00) |
             (tbl32(aes_sbox, state[2] & 0xFF) & 0x000000FF)) ^ u32(data, fki + 4)
    fs[2] = ((tbl32(aes_sbox, (state[2] >> 24) & 0xFF) & 0xFF000000) |
             (tbl32(aes_sbox, (state[1] >> 16) & 0xFF) & 0x00FF0000) |
             (tbl32(aes_sbox, (state[0] >> 8) & 0xFF) & 0x0000FF00) |
             (tbl32(aes_sbox, state[3] & 0xFF) & 0x000000FF)) ^ u32(data, fki + 8)
    fs[3] = ((tbl32(aes_sbox, (state[3] >> 24) & 0xFF) & 0xFF000000) |
             (tbl32(aes_sbox, (state[2] >> 16) & 0xFF) & 0x00FF0000) |
             (tbl32(aes_sbox, (state[1] >> 8) & 0xFF) & 0x0000FF00) |
             (tbl32(aes_sbox, state[0] & 0xFF) & 0x000000FF)) ^ u32(data, fki + 12)
    for i in range(4):
        w32(data, data_off + i * 4, bswap32(fs[i]))

def aes_decrypt(data, data_off, size, key_off):
    tmp2 = bytearray(16)
    rounds = u16(data, key_off + 2)
    for i in range(size >> 4):
        idx = data_off + i * 16
        tmp = bytearray(data[idx:idx + 16])
        aes_round(data, idx, key_off + 4, rounds)
        for j in range(16):
            data[idx + j] ^= tmp2[j]
        tmp2 = tmp


# ============================================================
# LZ Decompression
# ============================================================

def decompress(data, data_off, dest, key_off, s_size, d_size):
    shift = 0
    source = bytearray(s_size + 3)
    source[:s_size] = data[data_off:data_off + s_size]
    s_idx = 0
    count = 0
    tmp = 0
    tmp2 = 0
    FLAG_BIT = 32768
    FLAG_MASK = 32767

    while count < s_size and tmp2 < d_size:
        encoded = u32(source, s_idx) >> shift if s_idx + 3 < len(source) else 0
        lookup = key_off + (encoded & 0xFF) * 3
        code_word = u16(data, lookup)

        if code_word & FLAG_BIT:
            code_word &= FLAG_MASK
            code_len = data[lookup + 2]
        else:
            init_len = data[lookup + 2]
            bit_mask = 1 << init_len
            code_len = init_len + 1
            cur_idx = (code_word & FLAG_MASK) + (1 if (encoded & bit_mask) else 0)
            cur_code = u16(data, key_off + cur_idx * 3)
            while not (cur_code & FLAG_BIT):
                bit_mask <<= 1
                code_len += 1
                cur_idx = (cur_code & FLAG_MASK) + (1 if (encoded & bit_mask) else 0)
                cur_code = u16(data, key_off + cur_idx * 3)
            code_word = cur_code & FLAG_MASK

        shift += code_len
        bytes_consumed = shift // 8
        s_idx += bytes_consumed
        count += bytes_consumed
        shift %= 8

        op_type = code_word & 0x300
        op_data = code_word & 0xFF

        if op_type == 0x000:
            data[dest] = op_data & 0xFF
            dest += 1
            tmp2 += 1
        elif op_type == 0x100:
            if tmp >= 256:
                print(f'1.Data Corrupted: tmp={tmp}')
                return
            tmp = (tmp << 8 | op_data) if tmp != 0 else op_data
        elif op_type == 0x200:
            if tmp == 0:
                tmp = 1
            total = tmp * op_data
            if total + tmp2 > d_size:
                print(f'2.Data Corrupted')
                return
            if op_data == 1:
                for ii in range(tmp):
                    data[dest + ii] = data[dest - 1]
            elif op_data == 2:
                pat = u16(data, dest - 2)
                for ii in range(tmp):
                    w16(data, dest + ii * 2, pat)
            elif op_data == 4:
                pat = u32(data, dest - 4)
                for ii in range(tmp):
                    w32(data, dest + ii * 4, pat)
            dest += total
            tmp2 += total
            tmp = 0
        elif op_type == 0x300:
            copy_len = op_data
            if tmp2 + copy_len > d_size or tmp + copy_len > tmp2:
                print(f'3.Data Corrupted')
                return
            for ii in range(copy_len):
                data[dest + ii] = data[dest + ii - (tmp + copy_len)]
            dest += copy_len
            tmp2 += copy_len
            tmp = 0

    if tmp2 != d_size:
        print(f'Decompress: wrote 0x{tmp2:X} of 0x{d_size:X}')


# ============================================================
# Custom Decryptor Generator (x86 polymorphic code parser)
# ============================================================

def generate_custom_decryptor(data, data_off):
    ops = []
    pos = data_off
    OPMAP = {4: 'add', 44: 'sub', 52: 'xor', 144: 'nop', 192: 'grp2', 195: 'ret', 254: 'grp4'}

    opcode = data[pos]; pos += 1
    if opcode not in OPMAP:
        print(f'Unknown opcode 0x{opcode:02X} at 0x{pos-1:X}')
        return None

    while OPMAP[opcode] != 'ret':
        kind = OPMAP[opcode]
        if kind == 'add':
            val = data[pos]; pos += 1
            ops.append(('add', val))
        elif kind == 'sub':
            val = data[pos]; pos += 1
            ops.append(('sub', val))
        elif kind == 'xor':
            val = data[pos]; pos += 1
            ops.append(('xor', val))
        elif kind == 'nop':
            pass
        elif kind == 'grp2':
            modrm = data[pos]; pos += 1
            reg = (modrm >> 3) & 7
            imm = data[pos]; pos += 1
            if reg == 0:
                ops.append(('rol', imm))
            elif reg == 1:
                ops.append(('ror', imm))
            else:
                print(f'Unknown grp2 reg={reg}')
                return None
        elif kind == 'grp4':
            modrm = data[pos]; pos += 1
            reg = (modrm >> 3) & 7
            if reg == 0:
                ops.append(('inc',))
            else:
                ops.append(('dec',))

        opcode = data[pos]; pos += 1
        if opcode not in OPMAP:
            print(f'Unknown opcode 0x{opcode:02X} at 0x{pos-1:X}')
            return None

    def decryptor(b):
        for op in ops:
            if op[0] == 'add':
                b = (b + op[1]) & 0xFF
            elif op[0] == 'sub':
                b = (b - op[1]) & 0xFF
            elif op[0] == 'xor':
                b = b ^ op[1]
            elif op[0] == 'rol':
                b = rol8(b, op[1])
            elif op[0] == 'ror':
                b = ror8(b, op[1])
            elif op[0] == 'inc':
                b = (b + 1) & 0xFF
            elif op[0] == 'dec':
                b = (b - 1) & 0xFF
        return b
    return decryptor

# ============================================================
# DecryptAndDecompressData (common pipeline)
# ============================================================

def decrypt_and_decompress(data, data_off, key, key_offsets, custom_dec=None):
    src   = u32(data, data_off)
    s_sz  = u32(data, data_off + 4)
    dst   = u32(data, data_off + 8)
    d_sz  = u32(data, data_off + 12)

    aes_decrypt(data, src, s_sz, key_offsets[3])
    decrypt_data3(data, data_off, key, 19)

    if custom_dec is not None:
        for i in range(s_sz):
            data[src + i] = custom_dec(data[src + i])

    if s_sz != d_sz:
        decompress(data, src, dst, key_offsets[1], s_sz, d_sz)


# ============================================================
# Auto-locate functions
# ============================================================

def locate_shell_offsets(data, info):
    """Locate anchor and firstStageCS in shell region."""
    shell = info[6]
    shell_end = shell + info[5]  # approximate
    # scan for info[3] value in shell region
    anchor = None
    for off in range(shell, min(shell + 0x3000, len(data) - 0x100), 4):
        if u32(data, off) == info[3]:
            # verify: somewhere after this we find info[6]
            for delta in range(0x20, 0x60, 4):
                if off + delta < len(data) and u32(data, off + delta) == info[6]:
                    anchor = off
                    fcs = off + delta
                    print(f'  anchor = 0x{anchor:X} (shell+0x{anchor - shell:X})')
                    print(f'  firstStageCS = 0x{fcs:X} (anchor+0x{fcs - anchor:X})')
                    return anchor, fcs
    print('ERROR: cannot locate anchor in shell')
    return None, None

def find_tbl(data, info):
    """Locate the PE32 offset table in shell region using 0x58/0x88/0xF4 marker pattern."""
    shell = info[6]
    for off in range(shell, min(shell + 0x3000, len(data) - 0x100), 4):
        # tbl+0x58 is headerCS pairs, tbl+0x88 is (info[6], shell_size)
        # Verify: at candidate+0x88 we find info[6]
        candidate = off - 0x88
        if candidate < shell:
            continue
        if u32(data, off) == info[6]:
            # Double-check: at candidate+0xF4 should be a recognizable marker or
            # at candidate+0x88+4 should be a reasonable shell size
            shell_size_val = u32(data, off + 4)
            if 0x1000 < shell_size_val < 0x100000:
                # Verify tbl+0x58 area has plausible RVA pairs (non-zero)
                v58 = u32(data, candidate + 0x58)
                if 0 < v58 < len(data):
                    print(f'  tbl = 0x{candidate:X} (shell+0x{candidate - shell:X})')
                    return candidate
    print('ERROR: cannot locate tbl in shell (PE32)')
    return None

def locate_second_stage_offsets(data, ss, ss_size):
    """Locate thirdStageKey, checksum pairs, and bigThirdStage pair in secondStage."""
    # Method 1: find 3 consecutive zero uint32s
    three_zero_off = None
    for off in range(0, min(ss_size, 0x2000) - 12, 4):
        if u32(data, ss + off) == 0 and u32(data, ss + off + 4) == 0 and u32(data, ss + off + 8) == 0:
            # verify: 2 uints before should be non-zero (thirdStageKey, forthStageKey)
            if off >= 8 and u32(data, ss + off - 8) != 0:
                three_zero_off = off
                break
    if three_zero_off is None:
        print('ERROR: cannot find 3-zero marker in secondStage')
        return None

    third_key_off = three_zero_off - 8
    forth_key_off = three_zero_off - 4
    print(f'  thirdStageKey at ss+0x{third_key_off:X} = 0x{u32(data, ss + third_key_off):08X}')
    print(f'  forthStageKey at ss+0x{forth_key_off:X} = 0x{u32(data, ss + forth_key_off):08X}')

    # Checksum pairs are at fixed offsets relative to thirdStageKey:
    # +0x14 = secondStageCS, +0x1C = sevenStageCS, +0x24 = fifthStageCS, +0x2C = forthStageCS
    cs_base_off = third_key_off + 0x14
    print(f'  secondStageCS pair at ss+0x{cs_base_off:X}')
    print(f'  sevenStageCS pair at ss+0x{cs_base_off + 0x08:X}')
    print(f'  fifthStageCS pair at ss+0x{cs_base_off + 0x10:X}')
    print(f'  forthStageCS pair at ss+0x{cs_base_off + 0x18:X}')

    # Find bigThirdStage pair: scan for a pair where addr is valid and size >= 0x2000
    # The thirdStage pair is the one used for DecryptData3, located after the checksum area
    # It should be a (addr, size) where addr points into the image and size is large
    # We look starting from checksum area + some offset
    search_start = third_key_off + 0x40
    big_third_off = None
    for off in range(search_start, min(ss_size, 0x2000) - 8, 8):
        addr_val = u32(data, ss + off)
        size_val = u32(data, ss + off + 4)
        if 0x10000 < addr_val < len(data) and 0x2000 <= size_val <= 0x20000:
            # verify next 8 bytes is also a valid pair (the second thirdStage or same addr)
            addr2 = u32(data, ss + off + 8)
            size2 = u32(data, ss + off + 12)
            if addr2 == addr_val and 0x2000 <= size2 <= 0x20000:
                # Two consecutive pairs with same addr = (encrypted_pair, decrypted_pair) pattern
                # The second one (off+8) is the one we decrypt with DecryptData3
                big_third_off = off + 8
                print(f'  bigThirdStage pair at ss+0x{big_third_off:X} (addr=0x{addr2:X}, size=0x{size2:X})')
                break

    if big_third_off is None:
        # fallback: look for any pair with large size after search_start
        for off in range(search_start, min(ss_size, 0x2000) - 4, 4):
            addr_val = u32(data, ss + off)
            size_val = u32(data, ss + off + 4)
            if 0x10000 < addr_val < len(data) and 0x3000 <= size_val <= 0x10000:
                big_third_off = off
                print(f'  bigThirdStage pair (fallback) at ss+0x{big_third_off:X} (addr=0x{addr_val:X}, size=0x{size_val:X})')
                break

    if big_third_off is None:
        print('ERROR: cannot find bigThirdStage pair')
        return None

    return {
        'third_key_off': third_key_off,
        'forth_key_off': forth_key_off,
        'cs_base_off': cs_base_off,
        'big_third_off': big_third_off,
    }

def locate_third_stage_offsets(data, ts, ts_size):
    """Locate infoTable and keysAddr in thirdStage via brute-force marker search."""
    # scan for (type=1 or 0x11, valid_addr, valid_size, 0) followed by (type=2, ...)
    for off in range(0, ts_size - 32, 4):
        t0 = u32(data, ts + off)
        if t0 in (1, 0x11):
            # check next slot is type=2
            t1 = u32(data, ts + off + 16)
            if t1 == 2:
                # verify the addr in slot0 is reasonable
                addr0 = u32(data, ts + off + 4)
                if 0x1000 < addr0 < len(data):
                    info_table = ts + off
                    keys_addr = info_table - 0x58
                    print(f'  infoTable at ts+0x{off:X} (abs 0x{info_table:X})')
                    print(f'  keysAddr at ts+0x{off - 0x58:X} (abs 0x{keys_addr:X})')
                    return info_table, keys_addr
    print('ERROR: cannot locate infoTable in thirdStage')
    return None, None

def try_decrypt_third_stage(data, ss, third_key_off, big_third_off, in_place=False):
    """Try to decrypt bigThirdStage with the key, brute-force shift if needed.
    If in_place=True, the decrypted data stays at the original address (PE32 mode)."""
    key = u32(data, ss + third_key_off)
    pair_addr = ss + big_third_off
    ts_addr = u32(data, pair_addr)
    ts_size = u32(data, pair_addr + 4)

    # save original for retry
    backup = bytearray(data[ts_addr:ts_addr + ts_size])

    for shift in (19, 21, 17, 23, 15, 25, 13, 11):
        data[ts_addr:ts_addr + ts_size] = backup[:]
        w32(data, pair_addr, ts_addr)
        w32(data, pair_addr + 4, ts_size)
        decrypt_data3(data, pair_addr, key, shift)
        if in_place:
            # PE32: data decrypted in-place, use original address
            it, ka = locate_third_stage_offsets(data, ts_addr, ts_size)
            if it is not None:
                print(f'  thirdStage decrypted with shift={shift}, start=0x{ts_addr:X} (in-place)')
                return ts_addr, ts_size, it, ka, shift
        else:
            new_ts = u32(data, pair_addr)
            # verify: new_ts should be a valid address
            if 0x1000 < new_ts < len(data) - 0x100:
                # try to find infoTable
                it, ka = locate_third_stage_offsets(data, new_ts, ts_size)
                if it is not None:
                    print(f'  thirdStage decrypted with shift={shift}, start=0x{new_ts:X}')
                    return new_ts, ts_size, it, ka, shift
    print('ERROR: cannot decrypt thirdStage')
    return None, None, None, None, None


# ============================================================
# Main unpacker
# ============================================================

def main():
    if len(sys.argv) < 2:
        print('Usage: python decrypt_crackproof.py <input_file> [aes_tables_dir]')
        return

    in_file = sys.argv[1]
    aes_dir = sys.argv[2] if len(sys.argv) >= 3 else os.path.join('F:', os.sep, 'SEGA', 'DecryptCrackproofDll64')

    print(f'Loading AES tables from {aes_dir}')
    load_aes_tables(aes_dir)

    print(f'Reading {in_file}')
    file_data = bytearray(open(in_file, 'rb').read())

    # ---- Detect PE type ----
    pe_header = u32(file_data, 60)
    pe_magic = u16(file_data, pe_header + 24)
    is_pe32 = (pe_magic == 0x10B)
    print(f'PE type: {"PE32 (32-bit)" if is_pe32 else "PE32+ (64-bit)"}')

    # ---- Stage 1: Decrypt info ----
    print('\n=== Stage 1: DecryptData1 ===')
    info = decrypt_data1(file_data)
    for i in range(8):
        print(f'  info[{i}] = 0x{info[i]:08X}')
    if info[1] != 0x4E4E4F4B:
        print('ERROR: bad magic (not KONN)')
        return

    # ---- Stage 2: Decrypt shell region ----
    print('\n=== Stage 2: DecryptData2 (shell) ===')
    image_size = u32(file_data, pe_header + 80)
    data = bytearray(image_size)
    decrypt_size = info[6] - info[3] + 0x2000

    decrypt_data2(file_data, data, info, decrypt_size)
    # copy remaining unencrypted shell data
    src_off = info[4] + 0x1000 + decrypt_size
    dst_off = info[3] + decrypt_size
    remain = info[5] - decrypt_size
    data[dst_off:dst_off + remain] = file_data[src_off:src_off + remain]
    # write section base
    w32(data, info[3], 0x1000)
    # copy PE header
    data[:0x1000] = file_data[:0x1000]
    print(f'  image_size = 0x{image_size:X}, decrypt_size = 0x{decrypt_size:X}')

    # ---- Locate shell offsets ----
    print('\n=== Locating shell offsets ===')
    tbl = None
    anchor = None
    fcs = None
    if is_pe32:
        tbl = find_tbl(data, info)
        if tbl is None:
            return
    else:
        anchor, fcs = locate_shell_offsets(data, info)
        if anchor is None:
            return

    # ---- PE header restore (MUST be before checksum) ----
    print('\n=== PE header restore ===')
    if is_pe32:
        # PE32: direct writes from tbl offsets
        val_bc = u32(data, tbl + 0xBC)
        val_c8 = u32(data, tbl + 0xC8)
        val_cc = u32(data, tbl + 0xCC)
        w32(data, pe_header + 0x80, val_bc)
        w32(data, pe_header + 0x88, val_c8)
        w32(data, pe_header + 0x8C, val_cc)
        # TLS zero out
        w32(data, pe_header + 0xB0, 0)
        w32(data, pe_header + 0xB4, 0)
        print(f'  PE+0x80 = 0x{val_bc:X}, PE+0x88 = 0x{val_c8:X}, PE+0x8C = 0x{val_cc:X}')
    else:
        # PE32+: anchor-based
        import_rva  = u32(data, anchor + 0x08)
        import_size = u32(data, anchor + 0x04)
        w32(data, pe_header + 144, import_rva)
        w32(data, pe_header + 148, import_size)
        res_rva  = u32(data, fcs - 0x10)
        res_size = u32(data, fcs - 0x0C)
        w32(data, pe_header + 152, res_rva)
        w32(data, pe_header + 156, res_size)
        # TLS zero out
        w32(data, pe_header + 176, 0)
        w32(data, pe_header + 180, 0)
        print(f'  Import: RVA=0x{import_rva:X} Size=0x{import_size:X}')
        print(f'  Resource: RVA=0x{res_rva:X} Size=0x{res_size:X}')

    # ---- Checksums ----
    print('\n=== Computing checksums ===')
    if is_pe32:
        # PE32: headerCS pairs at tbl+0x58, RVA-based with crc32^size
        hcs_addr = tbl + 0x58
        header_checksum = 0
        while u32(data, hcs_addr + 4) != 0:
            pa = u32(data, hcs_addr)
            ps = u32(data, hcs_addr + 4)
            header_checksum ^= (crc32(data, pa, ps) ^ ps)
            hcs_addr += 8
        first_stage_cs = checksum_with_size_xor(data, tbl + 0xA8)
        second_stage_key = u32(data, tbl + 0x40)
    else:
        # PE32+: fcs-based
        hcs_addr = fcs + 0x80
        header_checksum = 0
        while u32(data, hcs_addr + 4) != 0:
            header_checksum ^= checksum_with_size_xor(data, hcs_addr)
            hcs_addr += 8
        first_stage_cs = checksum_with_size_xor(data, fcs)
        second_stage_key = u32(data, anchor + 0x14)
    print(f'  headerChecksum = 0x{header_checksum:08X}')
    print(f'  firstStageCS = 0x{first_stage_cs:08X}')
    print(f'  secondStageKey = 0x{second_stage_key:08X}')

    # ---- Stage 3: Decrypt secondStage ----
    print('\n=== Stage 3: SecondStage ===')
    if is_pe32:
        ss_pair = tbl + 0x98
    else:
        ss_pair = fcs + 0x40
    ss_key = (header_checksum ^ first_stage_cs ^ second_stage_key) & 0xFFFFFFFF
    decrypt_data3(data, ss_pair, ss_key, 21)
    ss = u32(data, ss_pair)
    ss_size = u32(data, ss_pair + 4)
    print(f'  secondStageStart = 0x{ss:08X}, size = 0x{ss_size:X}')

    # ---- Locate secondStage internal offsets ----
    print('\n=== Locating secondStage offsets ===')
    if is_pe32:
        # PE32: fixed offsets with shift for io4 shell
        # odd: ss_size=0xBC0, io4: ss_size=0xBD0 (all internal offsets shift by +0x10)
        ss_shift = ss_size - 0xBC0
        if ss_shift not in (0, 0x10):
            print(f'WARNING: unexpected ss_size 0x{ss_size:X}, ss_shift=0x{ss_shift:X}')
        shell_type = 'io4' if ss_shift else 'odd'
        print(f'  shell type: {shell_type} (ss_shift=0x{ss_shift:X})')
        third_key_off = 0x968 + ss_shift
        forth_key_off = 0x964 + ss_shift
        cs_base_off = 0x96C + ss_shift  # cs[0] at ss+0x96C/0x97C
        dp_base_off = 0xA9C + ss_shift
        print(f'  thirdStageKey at ss+0x{third_key_off:X} = 0x{u32(data, ss + third_key_off):08X}')
        print(f'  forthStageKey at ss+0x{forth_key_off:X} = 0x{u32(data, ss + forth_key_off):08X}')
        print(f'  CS pairs at ss+0x{cs_base_off:X}')
        print(f'  DP base at ss+0x{dp_base_off:X}')
    else:
        ss_offsets = locate_second_stage_offsets(data, ss, ss_size)
        if ss_offsets is None:
            return
        third_key_off = ss_offsets['third_key_off']
        forth_key_off = ss_offsets['forth_key_off']
        cs_base_off = ss_offsets['cs_base_off']
        big_third_off = ss_offsets['big_third_off']

    # ---- Stage 4: Decrypt thirdStage ----
    print('\n=== Stage 4: ThirdStage ===')
    if is_pe32:
        # PE32: thirdStage pair at ss+0xB8C/0xB9C (full encrypted size)
        # Data is decrypted in-place (addr doesn't change)
        third_pair_off = 0xB8C + ss_shift
        ts, ts_size, info_table, keys_addr, ts_shift = try_decrypt_third_stage(data, ss, third_key_off, third_pair_off, in_place=True)
    else:
        ts, ts_size, info_table, keys_addr, ts_shift = try_decrypt_third_stage(data, ss, third_key_off, big_third_off)
    if ts is None:
        return

    # ---- Process infoTable ----
    print('\n=== Processing infoTable ===')
    it_addr = info_table
    for j in range(2):
        tval = u32(data, it_addr)
        if tval in (1, 0x11):
            print(f'  slot{j}: type={tval} -> DecryptData4')
            decrypt_data4(data, it_addr + 4)
        elif tval == 2:
            print(f'  slot{j}: type=2 -> copy list')
            copy_addr = u32(data, it_addr + 4)
            while True:
                decrypt_data5(data, copy_addr, 16)
                src_a = u32(data, copy_addr)
                s_sz  = u32(data, copy_addr + 4)
                dst_a = u32(data, copy_addr + 8)
                d_sz  = u32(data, copy_addr + 12)
                copy_addr += 16
                if s_sz == 0:
                    break
                if src_a != 0 and dst_a != 0 and d_sz == s_sz:
                    data[dst_a:dst_a + s_sz] = data[src_a:src_a + s_sz]
        it_addr += 16

    # ---- Extract keyOffsets ----
    print('\n=== Extracting keyOffsets ===')
    key_offsets = [0] * 4
    ka = keys_addr
    for k in range(2):
        ka2 = ka
        for l in range(2):
            decrypt_data4(data, ka2)
            key_offsets[k * 2 + l] = u32(data, ka2)
            ka2 += 8
        ka += 32
    for i, ko in enumerate(key_offsets):
        print(f'  keyOffsets[{i}] = 0x{ko:08X}')

    # ---- Checksum addresses ----
    print('\n=== Checksum addresses ===')
    if is_pe32:
        # PE32: CS_B0 at tbl+0xB0, cs[0..3] at ss+cs_base_off
        # cs[0]=forthStageCS, cs[1]=fifthStageCS, cs[2]=sevenStageCS
        second_stage_cs_addr = tbl + 0xB0
        forth_stage_cs_addr  = ss + cs_base_off         # cs[0]
        fifth_stage_cs_addr  = ss + cs_base_off + 0x08  # cs[1]
        seven_stage_cs_addr  = ss + cs_base_off + 0x10  # cs[2]
        # cs[3] at ss + cs_base_off + 0x18 (unused directly here)
    else:
        # PE32+: secondStageCS is SHELL-relative (fcs - 8), others are ss-relative
        second_stage_cs_addr = fcs - 0x08
        seven_stage_cs_addr  = ss + cs_base_off + 0x08
        fifth_stage_cs_addr  = ss + cs_base_off + 0x10
        forth_stage_cs_addr  = ss + cs_base_off + 0x18
    print(f'  secondStageCS at 0x{second_stage_cs_addr:X}')
    print(f'  forthStageCS at 0x{forth_stage_cs_addr:X}')
    print(f'  fifthStageCS at 0x{fifth_stage_cs_addr:X}')
    print(f'  sevenStageCS at 0x{seven_stage_cs_addr:X}')

    # ---- Stage 5: ForthStage ----
    print('\n=== Stage 5: ForthStage ===')
    second_stage_cs = checksum_with_size_xor(data, second_stage_cs_addr)
    forth_stage_key_raw = u32(data, ss + forth_key_off)
    forth_stage_key = forth_stage_key_raw
    for m in range(4):
        n = 1
        while n <= ((m + 1) * 25) << 2:
            forth_stage_key = (forth_stage_key + n) & 0xFFFFFFFF
            n += 1

    if is_pe32:
        dp_base = ss + dp_base_off
        forth_addr = dp_base + 0x40   # DP[4]
    else:
        big_third_pair = ss + big_third_off
        forth_addr = big_third_pair + 0x50
    fk = (header_checksum ^ second_stage_cs ^ forth_stage_key) & 0xFFFFFFFF
    print(f'  forthStage pair at 0x{forth_addr:X}')
    print(f'  key = 0x{fk:08X}')
    decrypt_and_decompress(data, forth_addr, fk, key_offsets)

    # ---- Stage 6: FifthStage ----
    print('\n=== Stage 6: FifthStage ===')
    if is_pe32:
        fifth_addr = dp_base + 0x50   # DP[5]
    else:
        fifth_addr = big_third_pair + 0x60
    fifth_dsz = u32(data, fifth_addr + 12)  # save dSize before decrypt modifies pair
    print(f'  fifthStage pair at 0x{fifth_addr:X}, dSize=0x{fifth_dsz:X}')

    forth_cs = checksum_with_size_xor(data, forth_stage_cs_addr)
    forth_region_off = u32(data, forth_stage_cs_addr)
    forth_region_sz  = u32(data, forth_stage_cs_addr + 4)
    fifth_key = u32(data, forth_region_off + forth_region_sz - 4)
    fk5 = (header_checksum ^ forth_cs ^ fifth_key) & 0xFFFFFFFF
    print(f'  key = 0x{fk5:08X}')
    decrypt_and_decompress(data, fifth_addr, fk5, key_offsets)

    # ---- Stage 7: SevenStage ----
    print('\n=== Stage 7: SevenStage ===')
    if is_pe32:
        seven_addr = dp_base + 0x70   # DP[7]
    else:
        seven_addr = big_third_pair + 0x80
    seven_dsz = u32(data, seven_addr + 12)  # save dSize before decrypt
    print(f'  sevenStage pair at 0x{seven_addr:X}, dSize=0x{seven_dsz:X}')

    fifth_cs = checksum_with_size_xor(data, fifth_stage_cs_addr)
    fifth_start_actual = u32(data, fifth_addr)
    if is_pe32:
        # PE32: sevenKey at cs[1].addr + cs[1].size - 0x10, negated
        cs1_off = cs_base_off + 0x08  # cs[1] = fifthStageCS pair
        cs1_addr = u32(data, ss + cs1_off)
        cs1_size = u32(data, ss + cs1_off + 4)
        seven_key = (~u32(data, cs1_addr + cs1_size - 0x10)) & 0xFFFFFFFF
        print(f'  sevenKey from cs[1] 0x{cs1_addr:X}+0x{cs1_size:X}-0x10')
    else:
        # PE32+: sevenStageKey is at fifthStage end - 0x100
        seven_key_off = fifth_dsz - 0x100
        seven_key = (~u32(data, fifth_start_actual + seven_key_off)) & 0xFFFFFFFF
        print(f'  sevenKey at fifth+0x{seven_key_off:X}')
    fk7 = (header_checksum ^ fifth_cs ^ seven_key) & 0xFFFFFFFF
    print(f'  key = 0x{fk7:08X}')
    decrypt_and_decompress(data, seven_addr, fk7, key_offsets)

    # ---- Stage 8: EighthStage ----
    print('\n=== Stage 8: EighthStage ===')
    seven_start_actual = u32(data, seven_addr)

    if is_pe32:
        # PE32: key at sevenStage_start + (sevenDsz - 0xD0), advance_key(3)
        eighth_key_off = seven_dsz - 0xD0
        eighth_key = u32(data, seven_start_actual + eighth_key_off)
        for i2 in range(3):
            j2 = 1
            while j2 <= ((i2 + 1) * 25) << 2:
                eighth_key = (eighth_key + j2) & 0xFFFFFFFF
                j2 += 1
        print(f'  eighthStageKey at seven+0x{eighth_key_off:X} = 0x{eighth_key:08X}')

        # PE32: stage_dec LFSR — scan sevenStage backwards for valid LFSR block
        # LFSR block: 96 bytes, byte[95] = size, LFSR-decrypt first `size` bytes,
        # result must start with valid opcode and contain 0xC3 (ret)
        valid_opcodes = {0x04, 0x2C, 0x34, 0x90, 0xC0, 0xC3, 0xFE}
        custom_dec_off = None
        for scan_off in range(seven_dsz - 96, -1, -1):
            abs_off = seven_start_actual + scan_off
            sz = data[abs_off + 95]
            if sz < 10 or sz > 95:
                continue
            # full trial LFSR decrypt
            lfsr = 1
            decoded = bytearray(sz)
            src = data[abs_off:abs_off + sz]
            for bi in range(sz):
                b = src[bi]
                for bit in range(8):
                    b ^= ((lfsr & 1) << bit)
                    lfsr <<= 1
                    if lfsr & 0x8000: lfsr ^= 0x8003
                    lfsr &= 0xFFFF
                decoded[bi] = b
            if decoded[0] in valid_opcodes and 0xC3 in decoded:
                custom_dec_off = scan_off
                break
        if custom_dec_off is None:
            print('ERROR: could not locate customDecryptor in sevenStage (PE32)')
            return

        custom_dec_addr = seven_start_actual + custom_dec_off
        decrypt_data6(data, custom_dec_addr)
        custom_dec = generate_custom_decryptor(data, custom_dec_addr)
        if custom_dec is None:
            print('ERROR: failed to generate custom decryptor')
            return
        print(f'  customDecryptor at seven+0x{custom_dec_off:X}')
    else:
        # PE32+: Locate via INT3 padding scan
        eighth_key_off = None
        for scan_off in range(seven_dsz - 0x200, seven_dsz - 0x80, 4):
            if u32(data, seven_start_actual + scan_off) == 0xCCCCCCCC:
                eighth_key_off = scan_off + 4
                break
        if eighth_key_off is None:
            print('ERROR: could not locate INT3 padding in sevenStage')
            return

        # customDecryptor: scan from eighthStageKey forward for LFSR-encrypted x86 code
        valid_opcodes = {0x04, 0x2C, 0x34, 0x90, 0xC0, 0xC3, 0xFE}
        custom_dec_off = None
        for scan_off in range(eighth_key_off + 8, seven_dsz - 96):
            abs_off = seven_start_actual + scan_off
            sz = data[abs_off + 95]
            if sz < 10 or sz > 120:
                continue
            lfsr = 1; b = data[abs_off]
            for bit in range(8):
                b ^= ((lfsr & 1) << bit)
                lfsr <<= 1
                if lfsr & 0x8000: lfsr ^= 0x8003
                lfsr &= 0xFFFF
            if b in valid_opcodes:
                custom_dec_off = scan_off
                break
        if custom_dec_off is None:
            print('ERROR: could not locate customDecryptor in sevenStage')
            return

        print(f'  eighthStageKey at seven+0x{eighth_key_off:X}')
        print(f'  customDecryptor at seven+0x{custom_dec_off:X}')

        custom_dec_addr = seven_start_actual + custom_dec_off
        decrypt_data6(data, custom_dec_addr)
        custom_dec = generate_custom_decryptor(data, custom_dec_addr)
        if custom_dec is None:
            print('ERROR: failed to generate custom decryptor')
            return

        eighth_key = u32(data, seven_start_actual + eighth_key_off)
        for i2 in range(3):
            j2 = 1
            while j2 <= ((i2 + 1) * 25) << 2:
                eighth_key = (eighth_key + j2) & 0xFFFFFFFF
                j2 += 1

    seven_cs = checksum_with_size_xor(data, seven_stage_cs_addr)
    if is_pe32:
        eighth_addr = dp_base + 0xC0   # DP[12]
    else:
        eighth_addr = big_third_pair + 0xD0
    eighth_dsz = u32(data, eighth_addr + 12)  # save dSize before decrypt
    fk8 = (header_checksum ^ fifth_cs ^ seven_cs ^ eighth_key) & 0xFFFFFFFF
    print(f'  eighthStage pair at 0x{eighth_addr:X}, dSize=0x{eighth_dsz:X}')
    print(f'  key = 0x{fk8:08X}')
    decrypt_and_decompress(data, eighth_addr, fk8, key_offsets, custom_dec)

    # ============================================================
    # Final processing: file data decryption, imports, sections
    # ============================================================
    print('\n=== Final: File data decryption ===')
    eighth_start_actual = u32(data, eighth_addr)

    # EighthStage internal table offsets
    if is_pe32:
        # io4 shifts eighthStage internal offsets by the same ss_shift as secondStage
        off_import_table    = 0x3C50 + ss_shift
        off_file_cs         = 0x3C68 + ss_shift
        off_compressed_info = 0x3C78 + ss_shift
        off_zero_list       = 0x3C80 + ss_shift
        off_file_lfsr       = 0x40EC + ss_shift  # try shifted first, scan as fallback
    else:
        off_import_table    = 0x4DA8
        off_file_cs         = 0x4DB8
        off_compressed_info = 0x4DC0
        off_zero_list       = 0x4DC8
        off_file_lfsr       = 0x5120

    # File checksum processing
    file_cs_addrs = eighth_start_actual + off_file_cs
    file_cs_addr = u32(data, file_cs_addrs)
    file_cs_size = u32(data, file_cs_addrs + 4)
    print(f'  fileChecksumAddr = 0x{file_cs_addr:08X}, size = 0x{file_cs_size:X}')
    if file_cs_size > 0:
        file_cs_end = file_cs_addr + file_cs_size
        while file_cs_addr < file_cs_end:
            decrypt_data5(data, file_cs_addr, 16)
            file_cs_addr += 16
    else:
        while u32(data, file_cs_addr + 4) != 0:
            decrypt_data5(data, file_cs_addr, 16)
            file_cs_addr += 16

    # Generate file decryptor
    # Validate off_file_lfsr: LFSR block must have valid sz and decode to valid opcode
    def _validate_lfsr(off):
        if off + 96 > eighth_dsz:
            return False
        abs_off = eighth_start_actual + off
        sz = data[abs_off + 95]
        if sz < 10 or sz > 95:
            return False
        lfsr = 1; b = data[abs_off]
        for bit in range(8):
            b ^= ((lfsr & 1) << bit)
            lfsr <<= 1
            if lfsr & 0x8000: lfsr ^= 0x8003
            lfsr &= 0xFFFF
        return b in {0x04, 0x2C, 0x34, 0x90, 0xC0, 0xC3, 0xFE}

    if not _validate_lfsr(off_file_lfsr):
        # Scan eighthStage for LFSR block, prefer candidate closest to odd's 0x40EC
        valid_opcodes = {0x04, 0x2C, 0x34, 0x90, 0xC0, 0xC3, 0xFE}
        all_candidates = []
        for scan_off in range(off_zero_list, eighth_dsz - 95):
            abs_off = eighth_start_actual + scan_off
            sz = data[abs_off + 95]
            if sz < 10 or sz > 95:
                continue
            lfsr = 1
            decoded = bytearray(sz)
            src = data[abs_off:abs_off + sz]
            for bi in range(sz):
                b = src[bi]
                for bit in range(8):
                    b ^= ((lfsr & 1) << bit)
                    lfsr <<= 1
                    if lfsr & 0x8000: lfsr ^= 0x8003
                    lfsr &= 0xFFFF
                decoded[bi] = b
            if decoded[0] in valid_opcodes and 0xC3 in decoded:
                all_candidates.append((scan_off, sz, decoded[0]))
        if not all_candidates:
            print('ERROR: could not locate file LFSR in eighthStage')
            return
        best = min(all_candidates, key=lambda c: abs(c[0] - 0x40EC))
        off_file_lfsr = best[0]
    print(f'  fileLFSR at eighth+0x{off_file_lfsr:X}')
    file_dec_addr = eighth_start_actual + off_file_lfsr
    decrypt_data6(data, file_dec_addr)
    file_dec = generate_custom_decryptor(data, file_dec_addr)
    if file_dec is None:
        print('ERROR: failed to generate file decryptor')
        return

    # Save entry point from info[3]+0x10 before file decompression overwrites it
    original_ep = u32(data, info[3] + 0x10)
    # Save PE header directory values before file_data copy overwrites them
    if is_pe32:
        # PE32: we wrote to pe+0x80, pe+0x88, pe+0x8C
        saved_pe80 = u32(data, pe_header + 0x80)
        saved_pe88 = u32(data, pe_header + 0x88)
        saved_pe8c = u32(data, pe_header + 0x8C)
    else:
        saved_import_rva    = u32(data, pe_header + 144)
        saved_import_size   = u32(data, pe_header + 148)
        saved_resource_rva  = u32(data, pe_header + 152)
        saved_resource_size = u32(data, pe_header + 156)

    # Zero-out list from eighthStage table (must run BEFORE decompression)
    zero_list_addr = eighth_start_actual + off_zero_list
    zero_ptr = u32(data, zero_list_addr)
    zero_count = 0
    while True:
        decrypt_data5(data, zero_ptr, 16)
        src3  = u32(data, zero_ptr)
        s_sz3 = u32(data, zero_ptr + 4)
        zero_ptr += 16
        if s_sz3 == 0:
            break
        if src3 + s_sz3 > len(data):
            break
        for i4 in range(s_sz3):
            data[src3 + i4] = 0
        zero_count += 1
    print(f'  Zeroed {zero_count} regions')

    # Decompress/decrypt file data blocks
    compressed_info_addr = eighth_start_actual + off_compressed_info
    if is_pe32:
        compress_data_offset = ((~u32(file_data, 0x1080)) & 0xFFFFFFFF) + 0x1000
    else:
        compress_data_offset = ((~u32(file_data, 0x1080)) & 0xFFFFFFFF) + 0x1000
    compressed_info = u32(data, compressed_info_addr)
    print(f'  compressDataOffset = 0x{compress_data_offset:X}')
    print(f'  compressedDataInfo = 0x{compressed_info:08X}')

    block_count = 0
    while True:
        decrypt_data5(data, compressed_info, 16)
        src2  = u32(data, compressed_info)
        s_sz2 = u32(data, compressed_info + 4)
        dst2  = u32(data, compressed_info + 8)
        d_sz2 = u32(data, compressed_info + 12)
        compressed_info += 16
        if s_sz2 == 0:
            break
        # copy from original file
        file_src = src2 + compress_data_offset
        data[dst2:dst2 + s_sz2] = file_data[file_src:file_src + s_sz2]
        # AES decrypt
        aes_decrypt(data, dst2, s_sz2, key_offsets[2])
        # custom byte decrypt
        for i3 in range(s_sz2):
            data[dst2 + i3] = file_dec(data[dst2 + i3])
        # LZ decompress if needed
        if s_sz2 != d_sz2:
            decompress(data, dst2, dst2, key_offsets[0], s_sz2, d_sz2)
        block_count += 1
    print(f'  Decrypted {block_count} data blocks')

    # ---- Section table fixup ----
    print('\n=== Section table fixup ===')
    data[:0x1000] = file_data[:0x1000]
    opt_hdr_size = u16(file_data, pe_header + 20)
    sec_hdr = pe_header + 24 + opt_hdr_size

    export_va   = u32(file_data, pe_header + 24 + opt_hdr_size - 128)
    export_size = u32(file_data, pe_header + 24 + opt_hdr_size - 124)
    export_file_off = 0
    text_off = 0
    text_size = 0

    while u32(file_data, sec_hdr + 8) != 0:
        va   = u32(file_data, sec_hdr + 12)
        sz   = u32(file_data, sec_hdr + 8)
        f_off = u32(file_data, sec_hdr + 20)
        # check .text
        sec_name = file_data[sec_hdr:sec_hdr + 8]
        if sec_name[:5] == b'.text':
            text_size = sz
            text_off = va
        if export_va >= va and export_va + export_size <= va + sz:
            export_file_off = export_va - va + f_off
        # fix SizeOfRawData = VirtualSize, PointerToRawData = VirtualAddress
        w32(data, sec_hdr + 16, sz)
        w32(data, sec_hdr + 20, va)
        # .rdata needs RW for IAT (loader writes resolved addresses)
        if sec_name[:6] == b'.rdata':
            w32(data, sec_hdr + 36, 0xC0000040)  # IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA
        sec_hdr += 40

    if export_size != 0 and export_file_off != 0:
        data[export_va:export_va + export_size] = file_data[export_file_off:export_file_off + export_size]
        print(f'  Restored export table at 0x{export_va:X}')

    # ---- Decrypt .text section with decrypt_data8 (EXE only) ----
    # CrackProof encrypts .text per-page (0x1000 bytes) with decrypt_data8.
    # Key for page P = 0x8000 * (P + 1), loop starts from i=1 (skip block 0).
    if text_size > 0 and text_off > 0:
        print(f'\n=== Decrypting .text with decrypt_data8 ===')
        num_pages = text_size // 0x1000
        for page in range(num_pages):
            page_key = 0x8000 * (page + 1)
            page_addr = text_off + page * 0x1000
            # decrypt_data8 but skip i=0
            count = 0x1000 >> 4  # 256 blocks per page
            key = page_key
            # Advance key state for i=0 without XOR
            rk = ((key >> 15) | (key << 17)) & 0xFFFFFFFF
            key = rk  # ri = rk + 0, key = rk + 0
            # Process i=1..255
            for i in range(1, count):
                rk = ((key >> 15) | (key << 17)) & 0xFFFFFFFF
                ri = (rk + i) & 0xFFFFFFFF
                key = (ri + i) & 0xFFFFFFFF
                tidx = page_addr + i * 16 + (ri & 0xF)
                data[tidx] = (data[tidx] ^ key) & 0xFF
        print(f'  Decrypted {num_pages} pages')

    # ---- Fix data directories ----
    exe_pe = u32(data, 60)
    if is_pe32:
        # PE32: restore values we saved
        w32(data, exe_pe + 0x80, saved_pe80)
        w32(data, exe_pe + 0x88, saved_pe88)
        w32(data, exe_pe + 0x8C, saved_pe8c)
        # Zero out BaseReloc
        w32(data, exe_pe + 0xA0, 0)
        w32(data, exe_pe + 0xA4, 0)
        # Zero out TLS
        w32(data, exe_pe + 0xB0, 0)
        w32(data, exe_pe + 0xB4, 0)
    else:
        # PE32+: restore import/resource directories
        w32(data, exe_pe + 0x90, saved_import_rva)
        w32(data, exe_pe + 0x94, saved_import_size)
        w32(data, exe_pe + 0x98, saved_resource_rva)
        w32(data, exe_pe + 0x9C, saved_resource_size)
        # Zero out BaseReloc
        w32(data, exe_pe + 0xB0, 0)
        w32(data, exe_pe + 0xB4, 0)
    # Temporary EP (will be fixed after import name decryption)
    w32(data, exe_pe + 40, original_ep)

    # ---- Import table reconstruction ----
    print('\n=== Import table reconstruction ===')

    # Import table pointer from eighthStage
    import_table_addr = eighth_start_actual + off_import_table
    import_table_ptr = u32(data, import_table_addr)
    print(f'  importTable at eighth+0x{off_import_table:X} -> 0x{import_table_ptr:X}')

    if is_pe32:
        # PE32: 4-byte IAT entries
        # The real IDT is at import_table_ptr (from eighthStage), not the stub at pe+0x80
        thunk_size = 4
        ordinal_flag = 0x80000000
        idt_addr = import_table_ptr
        idt_size = u32(data, import_table_addr + 4)
        print(f'  Real IDT at 0x{idt_addr:X}, size=0x{idt_size:X}')

        idt_pos = idt_addr
        idt_end = idt_addr + idt_size  # limit traversal to declared size
        dll_count = 0
        while idt_pos + 20 <= idt_end:
            ilt_rva  = u32(data, idt_pos + 0)
            name_rva = u32(data, idt_pos + 12)
            iat_rva  = u32(data, idt_pos + 16)
            if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                break
            # Decrypt DLL name
            if 0 < name_rva < len(data):
                key = name_rva & 0xFF
                decrypt_data7(data, name_rva, key)
            # Decrypt function names via ILT (ILT and IAT share hint/name entries)
            thunk_pos = ilt_rva if (0 < ilt_rva < len(data)) else iat_rva
            if 0 < thunk_pos < len(data):
                while True:
                    thunk_val = u32(data, thunk_pos)
                    if thunk_val == 0:
                        break
                    if not (thunk_val & ordinal_flag):
                        if thunk_val + 2 < len(data):
                            key = thunk_val & 0xFF
                            decrypt_data7(data, thunk_val + 2, key)
                            w16(data, thunk_val, 0)  # clear hint
                    thunk_pos += thunk_size
            dll_count += 1
            idt_pos += 20
        print(f'  Decrypted names for {dll_count} DLLs')

        # Update PE header import directory to point to real IDT
        w32(data, exe_pe + 0x80, idt_addr)
        w32(data, exe_pe + 0x84, idt_size)

        # Fix IAT directory (pe+0xC0/0xC4): compute from IDT's IAT pointers
        iat_min = 0xFFFFFFFF
        iat_max = 0
        idt_scan = idt_addr
        while idt_scan + 20 <= idt_addr + idt_size:
            s_ilt = u32(data, idt_scan)
            s_name = u32(data, idt_scan + 12)
            s_iat = u32(data, idt_scan + 16)
            if s_ilt == 0 and s_name == 0 and s_iat == 0:
                break
            if s_iat < iat_min:
                iat_min = s_iat
            # Walk IAT to find end
            tp = s_iat
            while u32(data, tp) != 0:
                tp += 4
            tp += 4  # include null terminator
            if tp > iat_max:
                iat_max = tp
            idt_scan += 20
        if iat_min < iat_max:
            w32(data, exe_pe + 0xC0, iat_min)
            w32(data, exe_pe + 0xC4, iat_max - iat_min)
            print(f'  Updated IAT directory: RVA=0x{iat_min:X} Size=0x{iat_max - iat_min:X}')
    else:
        # PE32+: 8-byte IAT entries — full reconstruction
        # DLL name mapping based on function signatures (from Ghidra analysis)
        _dll_func_map = {
            'LookupPrivilegeValueA': 'ADVAPI32.DLL', 'DeregisterEventSource': 'ADVAPI32.DLL',
            'CertFindCertificateInStore': 'CRYPT32.DLL', 'CertCreateCertificateContext': 'CRYPT32.DLL',
            'DnsQueryEx': 'DNSAPI.DLL', 'DnsCancelQuery': 'DNSAPI.DLL',
            'DeleteObject': 'GDI32.DLL', 'GetDeviceCaps': 'GDI32.DLL',
            'HidD_GetManufacturerString': 'HID.DLL', 'HidD_GetHidGuid': 'HID.DLL',
            'IcmpSendEcho2': 'IPHLPAPI.DLL', 'GetBestRoute': 'IPHLPAPI.DLL',
            'WaitForSingleObject': 'KERNEL32.DLL', 'CloseHandle': 'KERNEL32.DLL',
            'WNetCancelConnection2W': 'MPR.DLL', 'WNetAddConnection2W': 'MPR.DLL',
            '_Nan': 'MSVCP110.DLL', '_Mtx_unlock': 'MSVCP110.DLL', '_Mtx_lock': 'MSVCP110.DLL',
            'abort': 'MSVCR110.DLL', 'malloc': 'MSVCR110.DLL', 'free': 'MSVCR110.DLL',
            'SetupDiGetDeviceInterfaceDetailW': 'SETUPAPI.DLL', 'CM_Get_Device_ID_ExA': 'CFGMGR32.DLL',
            'SHCreateDirectoryExW': 'SHELL32.DLL', 'SHFileOperationW': 'SHELL32.DLL',
            'PathFileExistsW': 'SHLWAPI.DLL', 'PathGetCharTypeW': 'SHLWAPI.DLL',
            'wsprintfW': 'USER32.DLL', 'EnumDisplayDevicesA': 'USER32.DLL', 'MessageBoxW': 'USER32.DLL',
            'WinHttpSetCredentials': 'WINHTTP.DLL', 'WinHttpOpen': 'WINHTTP.DLL',
            'timeBeginPeriod': 'WINMM.DLL', 'timeGetTime': 'WINMM.DLL',
            'WSAEventSelect': 'WS2_32.DLL', 'WSAStringToAddressA': 'WS2_32.DLL',
            'BCryptCloseAlgorithmProvider': 'BCRYPT.DLL', 'BCryptSetProperty': 'BCRYPT.DLL',
            'SymGetLineFromAddrW64': 'DBGHELP.DLL', 'SymInitializeW': 'DBGHELP.DLL',
            'CoTaskMemFree': 'COMBASE.DLL', 'CoCreateInstance': 'COMBASE.DLL',
            'WlanCloseHandle': 'WLANAPI.DLL', 'WlanOpenHandle': 'WLANAPI.DLL',
        }
        _ordinal_dll = 'THINCAPAYMENT.DLL'

        # Step 1: Walk IAT to find DLL groups
        iat_start = 0x5B1000
        pos = iat_start
        dll_groups = []
        while pos < iat_start + 0x4000:
            group_addr = pos
            entries = []
            while True:
                qval = struct.unpack_from('<Q', data, pos)[0]
                if qval == 0:
                    pos += 8
                    break
                entries.append(qval)
                pos += 8
            if not entries:
                break
            dll_groups.append((group_addr, entries))
        print(f'  Found {len(dll_groups)} IAT groups')

        # Step 2: Decrypt function names and identify DLLs
        dll_names = []
        for gi, (gaddr, entries) in enumerate(dll_groups):
            dll_name = None
            is_ordinal_only = True
            for qval in entries:
                rva = qval & 0xFFFFFFFF
                if qval & 0x8000000000000000:
                    continue
                if rva < 2 or rva >= len(data):
                    continue
                is_ordinal_only = False
                key = rva & 0xFF
                decrypt_data7(data, rva + 2, key)
                w16(data, rva, 0)
                nb = data[rva + 2:rva + 102]
                null_pos = nb.find(0)
                fname = nb[:null_pos].decode('ascii', errors='replace') if null_pos > 0 else ''
                if dll_name is None and fname in _dll_func_map:
                    dll_name = _dll_func_map[fname]
            if dll_name is None:
                if is_ordinal_only:
                    dll_name = _ordinal_dll
                else:
                    for qval in entries:
                        rva = qval & 0xFFFFFFFF
                        if qval & 0x8000000000000000 or rva < 2 or rva >= len(data):
                            continue
                        nb = data[rva + 2:rva + 102]
                        null_pos = nb.find(0)
                        fname = nb[:null_pos].decode('ascii', errors='replace') if null_pos > 0 else ''
                        if 'basic_streambuf' in fname or 'locale' in fname or '_Mtx' in fname:
                            dll_name = 'MSVCP110.DLL'; break
                        if 'abort' in fname or 'malloc' in fname or '__CxxFrameHandler' in fname:
                            dll_name = 'MSVCR110.DLL'; break
            if dll_name is None:
                dll_name = f'UNKNOWN_{gi}.DLL'
            dll_names.append(dll_name)
            print(f'  DLL[{gi}] = {dll_name} ({len(entries)} functions)')

        # Step 3: Build new import directory
        idt_base = 0xB34730
        idt_size = (len(dll_groups) + 1) * 20
        name_base = idt_base + idt_size
        name_off = name_base
        dll_name_rvas = []
        for dname in dll_names:
            dll_name_rvas.append(name_off)
            name_bytes = dname.encode('ascii') + b'\x00'
            data[name_off:name_off + len(name_bytes)] = name_bytes
            name_off += len(name_bytes)
            if name_off & 1:
                name_off += 1

        ilt_base = (name_off + 7) & ~7
        ilt_off = ilt_base
        ilt_rvas = []
        for gi, (gaddr, entries) in enumerate(dll_groups):
            ilt_rvas.append(ilt_off)
            for qval in entries:
                struct.pack_into('<Q', data, ilt_off, qval)
                ilt_off += 8
            struct.pack_into('<Q', data, ilt_off, 0)
            ilt_off += 8

        total_size = ilt_off - idt_base
        print(f'  Import directory at 0x{idt_base:X}, total size 0x{total_size:X}')

        # Step 4: Write IDT entries
        for gi, (gaddr, entries) in enumerate(dll_groups):
            idt_entry = idt_base + gi * 20
            w32(data, idt_entry + 0, ilt_rvas[gi])
            w32(data, idt_entry + 4, 0)
            w32(data, idt_entry + 8, 0)
            w32(data, idt_entry + 12, dll_name_rvas[gi])
            w32(data, idt_entry + 16, gaddr)
        idt_term = idt_base + len(dll_groups) * 20
        data[idt_term:idt_term + 20] = b'\x00' * 20

        # Step 5: Update PE header import directory
        w32(data, exe_pe + 0x90, idt_base)
        w32(data, exe_pe + 0x94, len(dll_groups) * 20 + 20)
        print(f'  Updated PE import directory: RVA=0x{idt_base:X} Size=0x{len(dll_groups)*20+20:X}')

        # Step 6: Fix IAT data directory (directory #12, at pe+0xE8)
        iat_end = dll_groups[-1][0] + len(dll_groups[-1][1]) * 8 + 8
        iat_total_size = iat_end - iat_start
        w32(data, exe_pe + 0xE8, iat_start)
        w32(data, exe_pe + 0xEC, iat_total_size)
        print(f'  Updated IAT directory: RVA=0x{iat_start:X} Size=0x{iat_total_size:X}')

    # Fix PE header fields
    if is_pe32:
        # PE32: DllCharacteristics at pe+0x5E — clear ASLR/DEP
        # Subsystem is already correct from file_data restore
        w16(data, exe_pe + 0x5E, 0)
    else:
        # PE32+: Subsystem at pe+92, DllCharacteristics at pe+94
        w16(data, exe_pe + 92, 3)
        w16(data, exe_pe + 94, 0)

    # ---- Fix entry point ----
    print('\n=== Entry point fix ===')
    real_ep = original_ep  # fallback
    if is_pe32:
        # PE32: the original file's EP is correct (not modified by CrackProof)
        # Section table fixup already restored file_data[:0x1000] which includes the PE header
        real_ep = u32(file_data, pe_header + 40)
        print(f'  Using original file entry point = 0x{real_ep:X}')
    else:
        # PE32+: Pattern: sub rsp,0x28; call xxx; add rsp,0x28; jmp xxx
        ep_pattern_pre = bytes([0x48, 0x83, 0xEC, 0x28])
        ep_pattern_mid = bytes([0x48, 0x83, 0xC4, 0x28])
        for addr in range(0x1000, min(len(data) - 20, 0x5B1000)):
            if data[addr:addr+4] == ep_pattern_pre and data[addr+4] == 0xE8:
                if data[addr+9:addr+13] == ep_pattern_mid and data[addr+13] == 0xE9:
                    real_ep = addr
                    break
        print(f'  Entry point = 0x{real_ep:X} (original was 0x{original_ep:X})')
    w32(data, exe_pe + 40, real_ep)

    # ---- Write output ----
    dot = in_file.rfind('.')
    if dot >= 0:
        out_file = in_file[:dot] + '.unpack' + in_file[dot:]
    else:
        out_file = in_file + '.unpack'
    print(f'\n=== Writing {out_file} ===')
    with open(out_file, 'wb') as f:
        f.write(data)
    print('Done!')


if __name__ == '__main__':
    main()
