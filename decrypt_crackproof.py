import struct
import os
import sys
import zlib
import array
import time as _time

# ============================================================
# CrackProof Shell Unpacker (DLL + EXE, PE32 + PE32+)
# Auto-locate offsets, 8-stage decryption chain
# Reference: DecryptCrackproofDll64 (C#)
# ============================================================

_t0 = _time.perf_counter()
def _elapsed():
    return f'[{_time.perf_counter()-_t0:.2f}s]'

# ---------- helpers ----------
_u16 = struct.Struct('<H')
_u32 = struct.Struct('<I')
_u64 = struct.Struct('<Q')

def u8(data, off):
    return data[off]

def u16(data, off):
    return _u16.unpack_from(data, off)[0]

def u32(data, off):
    return _u32.unpack_from(data, off)[0]

def u64(data, off):
    return _u64.unpack_from(data, off)[0]

def w8(data, off, val):
    data[off] = val & 0xFF

def w16(data, off, val):
    _u16.pack_into(data, off, val & 0xFFFF)

def w32(data, off, val):
    _u32.pack_into(data, off, val & 0xFFFFFFFF)

def w64(data, off, val):
    _u64.pack_into(data, off, val & 0xFFFFFFFFFFFFFFFF)

def bswap32(v):
    return int.from_bytes((v & 0xFFFFFFFF).to_bytes(4, 'little'), 'big')

# Pre-built ror8/rol8 lookup tables: _ROR8[shift][byte], _ROL8[shift][byte]
_ROR8 = [[0]*256 for _ in range(8)]
_ROL8 = [[0]*256 for _ in range(8)]
for _s in range(8):
    for _b in range(256):
        _ROR8[_s][_b] = ((_b >> _s) | (_b << (8 - _s))) & 0xFF
        _ROL8[_s][_b] = ((_b << _s) | (_b >> (8 - _s))) & 0xFF

def ror8(b, n):
    return _ROR8[n & 7][b]

def rol8(b, n):
    return _ROL8[n & 7][b]

def get_string(data, off):
    end = data.index(0, off) if 0 in data[off:off+512] else off + 512
    return data[off:end].decode('ascii', errors='replace')

# ---------- CRC32 (use zlib C implementation) ----------
def crc32(data, offset, size, init=0):
    return zlib.crc32(data[offset:offset + size], init) & 0xFFFFFFFF

def checksum_with_size_xor(data, addr):
    off = u32(data, addr)
    sz = u32(data, addr + 4)
    return crc32(data, off, sz) ^ sz

# ---------- DecryptData1..8 ----------
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

def decrypt_data2(file_data, data, info, decrypt_size):
    offset = info[4] + 4096
    tmp = (info[0] + (~decrypt_size & 0xFFFFFFFF)) & 0xFFFFFFFF
    count = decrypt_size >> 2
    # Batch read source dwords
    src_bytes = file_data[offset:offset + count * 4]
    vals = struct.unpack_from(f'<{count}I', src_bytes, 0)
    dst_off = info[3]
    for i in range(count):
        val = vals[i]
        _u32.pack_into(data, dst_off + i * 4, (tmp ^ val) & 0xFFFFFFFF)
        tmp = ((i * i) ^ ((tmp + val + i) & 0xFFFFFFFF)) & 0xFFFFFFFF

def decrypt_data3(data, data_offset, key, shift):
    off = u32(data, data_offset)
    sz = u32(data, data_offset + 4)
    rev = 32 - shift
    count = sz >> 2
    M = 0xFFFFFFFF
    for i in range(count):
        addr = off + i * 4
        val = _u32.unpack_from(data, addr)[0] ^ key
        key = (key + i) & M
        val = (((val >> shift) | (val << rev)) & M)
        val = (val - i) & M
        _u32.pack_into(data, addr, val)

# Pre-build decrypt_data4 transform: ror5(b) ^ key2 -> ror5 -> ^ key1 -> ror5
# Since keys cycle 0-255, pre-build 256 full-byte LUTs for decrypt_data4 and decrypt_data5
_d4_lut = None  # [key1][key2][byte] -> result
_d5_lut = None

def _build_d4_lut():
    global _d4_lut
    if _d4_lut is not None:
        return
    ror5 = _ROR8[5]
    _d4_lut = [[None]*256 for _ in range(256)]
    for k1 in range(256):
        for k2 in range(256):
            tbl = bytearray(256)
            for b in range(256):
                v = ror5[b] ^ k2
                v = ror5[v] ^ k1
                v = ror5[v]
                tbl[b] = v
            _d4_lut[k1][k2] = tbl

def _build_d5_lut():
    global _d5_lut
    if _d5_lut is not None:
        return
    ror6 = _ROR8[6]
    _d5_lut = [[None]*256 for _ in range(256)]
    for k1 in range(256):
        for k2 in range(256):
            tbl = bytearray(256)
            for b in range(256):
                v = ror6[b] ^ k2
                v = ror6[v] ^ k1
                v = ror6[v]
                tbl[b] = v
            _d5_lut[k1][k2] = tbl

def decrypt_data4(data, data_offset):
    _build_d4_lut()
    va = u32(data, data_offset)
    sz = u32(data, data_offset + 4)
    key1 = ((va >> 8) + va) & 0xFF
    key2 = (key1 + 1) & 0xFF
    for i in range(sz):
        tbl = _d4_lut[key1][key2]
        data[va + i] = tbl[data[va + i]]
        key1 = (key1 + 1) & 0xFF
        key2 = (key2 + 1) & 0xFF

def decrypt_data5(data, va, size):
    _build_d5_lut()
    key1 = va & 0xFF
    key2 = (key1 + 1) & 0xFF
    for i in range(size):
        tbl = _d5_lut[key1][key2]
        data[va + i] = tbl[data[va + i]]
        key1 = (key1 + 1) & 0xFF
        key2 = (key2 + 1) & 0xFF

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

def decrypt_data8(data, data_offset, size, key):
    count = size >> 4
    for i in range(count):
        rk = ((key >> 15) | (key << 17)) & 0xFFFFFFFF
        ri = (rk + i) & 0xFFFFFFFF
        key = (ri + i) & 0xFFFFFFFF
        tidx = data_offset + i * 16 + (ri & 0xF)
        data[tidx] = (data[tidx] ^ key) & 0xFF

# ---------- AES (optimized: array.array for direct indexing) ----------
_cm1 = _cm2 = _cm3 = _cm4 = _sbox = None  # array.array('I')

def load_aes_tables(base_dir):
    global _cm1, _cm2, _cm3, _cm4, _sbox
    def _load(name):
        raw = open(os.path.join(base_dir, name), 'rb').read()
        return array.array('I', raw)  # native u32 array, direct index
    _cm1 = _load('aes_colum_mix1')
    _cm2 = _load('aes_colum_mix2')
    _cm3 = _load('aes_colum_mix3')
    _cm4 = _load('aes_colum_mix4')
    _sbox = _load('aes_sbox')

def aes_round(data, data_off, key_off, rounds):
    # Read 16-byte block as 4 big-endian u32, XOR with round key 0
    cm1, cm2, cm3, cm4, sb = _cm1, _cm2, _cm3, _cm4, _sbox
    s0 = bswap32(_u32.unpack_from(data, data_off)[0])      ^ _u32.unpack_from(data, key_off)[0]
    s1 = bswap32(_u32.unpack_from(data, data_off + 4)[0])  ^ _u32.unpack_from(data, key_off + 4)[0]
    s2 = bswap32(_u32.unpack_from(data, data_off + 8)[0])  ^ _u32.unpack_from(data, key_off + 8)[0]
    s3 = bswap32(_u32.unpack_from(data, data_off + 12)[0]) ^ _u32.unpack_from(data, key_off + 12)[0]
    for r in range(1, rounds):
        ki = key_off + r * 16
        k0 = _u32.unpack_from(data, ki)[0]
        k1 = _u32.unpack_from(data, ki + 4)[0]
        k2 = _u32.unpack_from(data, ki + 8)[0]
        k3 = _u32.unpack_from(data, ki + 12)[0]
        t0 = cm2[(s3>>16)&0xFF] ^ cm3[(s2>>8)&0xFF] ^ cm1[(s0>>24)&0xFF] ^ cm4[s1&0xFF] ^ k0
        t1 = cm2[(s0>>16)&0xFF] ^ cm1[(s1>>24)&0xFF] ^ cm3[(s3>>8)&0xFF] ^ cm4[s2&0xFF] ^ k1
        t2 = cm2[(s1>>16)&0xFF] ^ cm3[(s0>>8)&0xFF] ^ cm1[(s2>>24)&0xFF] ^ cm4[s3&0xFF] ^ k2
        t3 = cm3[(s1>>8)&0xFF] ^ cm2[(s2>>16)&0xFF] ^ cm1[(s3>>24)&0xFF] ^ cm4[s0&0xFF] ^ k3
        s0, s1, s2, s3 = t0, t1, t2, t3
    # Final round (sbox only)
    fki = key_off + rounds * 16
    fk0 = _u32.unpack_from(data, fki)[0]
    fk1 = _u32.unpack_from(data, fki + 4)[0]
    fk2 = _u32.unpack_from(data, fki + 8)[0]
    fk3 = _u32.unpack_from(data, fki + 12)[0]
    f0 = ((sb[(s0>>24)&0xFF]&0xFF000000)|(sb[(s3>>16)&0xFF]&0x00FF0000)|(sb[(s2>>8)&0xFF]&0x0000FF00)|(sb[s1&0xFF]&0x000000FF)) ^ fk0
    f1 = ((sb[(s1>>24)&0xFF]&0xFF000000)|(sb[(s0>>16)&0xFF]&0x00FF0000)|(sb[(s3>>8)&0xFF]&0x0000FF00)|(sb[s2&0xFF]&0x000000FF)) ^ fk1
    f2 = ((sb[(s2>>24)&0xFF]&0xFF000000)|(sb[(s1>>16)&0xFF]&0x00FF0000)|(sb[(s0>>8)&0xFF]&0x0000FF00)|(sb[s3&0xFF]&0x000000FF)) ^ fk2
    f3 = ((sb[(s3>>24)&0xFF]&0xFF000000)|(sb[(s2>>16)&0xFF]&0x00FF0000)|(sb[(s1>>8)&0xFF]&0x0000FF00)|(sb[s0&0xFF]&0x000000FF)) ^ fk3
    _u32.pack_into(data, data_off,      bswap32(f0))
    _u32.pack_into(data, data_off + 4,  bswap32(f1))
    _u32.pack_into(data, data_off + 8,  bswap32(f2))
    _u32.pack_into(data, data_off + 12, bswap32(f3))

def aes_decrypt(data, data_off, size, key_off):
    prev = bytearray(16)
    rounds = u16(data, key_off + 2)
    koff = key_off + 4
    nblocks = size >> 4
    for i in range(nblocks):
        idx = data_off + i * 16
        cipher = bytearray(data[idx:idx+16])
        aes_round(data, idx, koff, rounds)
        # CBC XOR (16 bytes at a time via int)
        p = int.from_bytes(data[idx:idx+16], 'little') ^ int.from_bytes(prev, 'little')
        data[idx:idx+16] = p.to_bytes(16, 'little')
        prev = cipher

# ---------- LZ Decompression ----------
def decompress(data, data_off, dest, key_off, s_size, d_size, verbose=False):
    if verbose:
        print(f'    [Decompress] src=0x{data_off:X} dst=0x{dest:X} key=0x{key_off:X} sSize=0x{s_size:X} dSize=0x{d_size:X}')
    shift = 0
    source = bytearray(s_size + 3)
    source[:s_size] = data[data_off:data_off + s_size]
    s_idx = 0; count = 0; tmp = 0; tmp2 = 0
    FLAG_BIT = 32768; FLAG_MASK = 32767
    debug_ops = 0

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

        debug_ops += 1

        if op_type == 0x000:
            data[dest] = op_data & 0xFF
            dest += 1; tmp2 += 1
        elif op_type == 0x100:
            if tmp >= 256:
                if verbose: print(f'1.Data Corrupted: tmp={tmp}')
                return False
            tmp = (tmp << 8 | op_data) if tmp != 0 else op_data
        elif op_type == 0x200:
            if tmp == 0: tmp = 1
            total = tmp * op_data
            if total + tmp2 > d_size:
                if verbose: print(f'2.Data Corrupted')
                return False
            if op_data == 1:
                for ii in range(tmp): data[dest+ii] = data[dest-1]
            elif op_data == 2:
                pat = u16(data, dest-2)
                for ii in range(tmp): w16(data, dest+ii*2, pat)
            elif op_data == 4:
                pat = u32(data, dest-4)
                for ii in range(tmp): w32(data, dest+ii*4, pat)
            dest += total; tmp2 += total; tmp = 0
        elif op_type == 0x300:
            copy_len = op_data
            if tmp2 + copy_len > d_size or tmp + copy_len > tmp2:
                if verbose: print(f'3.Data Corrupted')
                return False
            for ii in range(copy_len):
                data[dest+ii] = data[dest+ii-(tmp+copy_len)]
            dest += copy_len; tmp2 += copy_len; tmp = 0

    if tmp2 != d_size:
        if verbose: print(f'    Decompress FAILED: wrote 0x{tmp2:X} of 0x{d_size:X}')
        return False
    else:
        return True

# ---------- Custom Decryptor Generator (256-byte LUT) ----------
def generate_custom_decryptor(data, data_off):
    ops = []
    pos = data_off
    OPMAP = {4:'add', 44:'sub', 52:'xor', 144:'nop', 192:'grp2', 195:'ret', 254:'grp4'}
    opcode = data[pos]; pos += 1
    if opcode not in OPMAP:
        print(f'Unknown opcode 0x{opcode:02X}')
        return None
    while OPMAP[opcode] != 'ret':
        kind = OPMAP[opcode]
        if kind == 'add':    val = data[pos]; pos += 1; ops.append(('add', val))
        elif kind == 'sub':  val = data[pos]; pos += 1; ops.append(('sub', val))
        elif kind == 'xor':  val = data[pos]; pos += 1; ops.append(('xor', val))
        elif kind == 'nop':  pass
        elif kind == 'grp2':
            modrm = data[pos]; pos += 1
            reg = (modrm >> 3) & 7
            imm = data[pos]; pos += 1
            if reg == 0:   ops.append(('rol', imm))
            elif reg == 1: ops.append(('ror', imm))
            else: print(f'Unknown grp2 reg={reg}'); return None
        elif kind == 'grp4':
            modrm = data[pos]; pos += 1
            reg = (modrm >> 3) & 7
            ops.append(('inc',) if reg == 0 else ('dec',))
        opcode = data[pos]; pos += 1
        if opcode not in OPMAP:
            print(f'Unknown opcode 0x{opcode:02X}')
            return None
    # Build 256-byte LUT
    lut = bytearray(256)
    for b in range(256):
        v = b
        for op in ops:
            if   op[0] == 'add': v = (v + op[1]) & 0xFF
            elif op[0] == 'sub': v = (v - op[1]) & 0xFF
            elif op[0] == 'xor': v = v ^ op[1]
            elif op[0] == 'rol': v = _ROL8[op[1] & 7][v]
            elif op[0] == 'ror': v = _ROR8[op[1] & 7][v]
            elif op[0] == 'inc': v = (v + 1) & 0xFF
            elif op[0] == 'dec': v = (v - 1) & 0xFF
        lut[b] = v
    # Return translate table for bytes.translate() and also a direct LUT
    _translate_tbl = bytes.maketrans(bytes(range(256)), bytes(lut))
    return lut, _translate_tbl

# ---------- DecryptAndDecompress ----------
def decrypt_and_decompress(data, data_off, key, key_offsets, custom_dec=None, verbose=False):
    src  = u32(data, data_off)
    s_sz = u32(data, data_off + 4)
    dst  = u32(data, data_off + 8)
    d_sz = u32(data, data_off + 12)
    if verbose:
        print(f'    DAD: src=0x{src:X} s_sz=0x{s_sz:X} dst=0x{dst:X} d_sz=0x{d_sz:X}')
    aes_decrypt(data, src, s_sz, key_offsets[3])
    decrypt_data3(data, data_off, key, 19)
    if custom_dec is not None:
        _lut, _tt = custom_dec
        # Bulk translate using bytes.translate (C-speed)
        data[src:src + s_sz] = bytearray(bytes(data[src:src + s_sz]).translate(_tt))
    if s_sz != d_sz:
        return decompress(data, src, dst, key_offsets[1], s_sz, d_sz, verbose=verbose)
    return True

# ---------- advance_key helper ----------
def advance_key(key, iterations):
    for m in range(iterations):
        n = 1
        while n <= ((m + 1) * 25) << 2:
            key = (key + n) & 0xFFFFFFFF
            n += 1
    return key

# ---------- Find LFSR block in a region ----------
def find_lfsr_block(data, base, size, start_off=0, scan_backward=False):
    valid_opcodes = {0x04, 0x2C, 0x34, 0x90, 0xC0, 0xC3, 0xFE}
    scan_range = range(start_off, size - 95) if not scan_backward else range(size - 96, start_off - 1, -1)
    for scan_off in scan_range:
        abs_off = base + scan_off
        sz = data[abs_off + 95]
        if sz < 10 or sz > 95:
            continue
        lfsr = 1
        decoded = bytearray(sz)
        for bi in range(sz):
            b = data[abs_off + bi]
            for bit in range(8):
                b ^= ((lfsr & 1) << bit)
                lfsr <<= 1
                if lfsr & 0x8000: lfsr ^= 0x8003
                lfsr &= 0xFFFF
            decoded[bi] = b
        if decoded[0] in valid_opcodes and 0xC3 in decoded:
            # Extra validation: check ALL opcodes in the decoded sequence are valid
            pos = 0
            valid = True
            while pos < sz:
                if decoded[pos] not in valid_opcodes:
                    valid = False
                    break
                op = decoded[pos]; pos += 1
                if op == 0xC3:  # RET
                    break
                elif op == 0x90:  # NOP
                    pass
                elif op in (0x04, 0x2C, 0x34):  # ADD/SUB/XOR imm8
                    pos += 1
                elif op == 0xC0:  # Group2 (modrm + imm8)
                    pos += 2
                elif op == 0xFE:  # Group4 (modrm)
                    pos += 1
            if valid:
                return scan_off
    return None


# ============================================================
# Auto-locate functions (PE32 only)
# ============================================================

def find_tbl(data, info):
    shell = info[6]
    for off in range(shell, min(shell + 0x3000, len(data) - 0x100), 4):
        candidate = off - 0x88
        if candidate < shell:
            continue
        if u32(data, off) == info[6]:
            shell_size_val = u32(data, off + 4)
            if 0x1000 < shell_size_val < 0x100000:
                v58 = u32(data, candidate + 0x58)
                if 0 < v58 < len(data):
                    return candidate
    return None


# ============================================================
# PE32+ offset structure (from C# reference)
# ============================================================
# Shell region (info[6]-relative, via anchor/fcs):
#   anchor = scan for info[3] in shell, verified by info[6] at anchor+0x38
#   fcs = anchor + 0x38  (firstStageCS pair)
#   secondStageKey = anchor + 0x14
#   import_rva = anchor + 0x08
#   import_size = anchor + 0x04
#   resource_rva = fcs - 0x10
#   resource_size = fcs - 0x0C
#   secondStageCS pair = fcs - 0x08
#   headerCS pairs = fcs + 0x80
#   secondStage pair = fcs + 0x40
#
# SecondStage (ss-relative, ss_size=0x10C8 baseline):
#   thirdStageKey  = ss + 0x0D74
#   forthStageKey  = ss + 0x0D78
#   CS pairs: secondCS=ss+0xD88, sevenCS=ss+0xD90, fifthCS=ss+0xD98, forthCS=ss+0xDA0
#   thirdStage pair  = ss + 0x0E30
#   forthStage pair  = ss + 0x0E80
#   fifthStage pair  = ss + 0x0E90
#   sevenStage pair  = ss + 0x0EB0
#   eighthStage pair = ss + 0x0F00
#
# ThirdStage (ts-relative):
#   keysAddr   = ts + 0x23C8
#   infoTable  = ts + 0x2420
#
# SevenStage (seven-relative):
#   eighthStageKey = seven + 0x0C58
#   customDecryptor= seven + 0x0C80
#
# EighthStage (eighth-relative):
#   compressedInfo = eighth + 0x2EC8
#   importTable    = eighth + 0x2EF0
#   fileChecksums  = eighth + 0x3018
#   fileDecryptor  = eighth + 0x3070 (= 0x3018 + 0x58)


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
    src_off = info[4] + 0x1000 + decrypt_size
    dst_off = info[3] + decrypt_size
    remain = info[5] - decrypt_size
    data[dst_off:dst_off + remain] = file_data[src_off:src_off + remain]
    w32(data, info[3], 0x1000)
    data[:0x1000] = file_data[:0x1000]
    print(f'  image_size = 0x{image_size:X}, decrypt_size = 0x{decrypt_size:X}')

    # ============================================================
    # PE32+ (64-bit) processing — fixed offsets from C# reference
    # ============================================================
    if not is_pe32:
        # ---- Locate anchor in shell ----
        print('\n=== Locating shell offsets ===')
        shell = info[6]
        anchor = None
        fcs = None
        for off in range(shell, min(shell + 0x3000, len(data) - 0x100), 4):
            if u32(data, off) == info[3]:
                for delta in range(0x20, 0x60, 4):
                    if off + delta < len(data) and u32(data, off + delta) == info[6]:
                        anchor = off
                        fcs = off + delta
                        break
                if anchor is not None:
                    break
        if anchor is None:
            print('ERROR: cannot locate anchor in shell')
            return
        print(f'  anchor = 0x{anchor:X} (shell+0x{anchor-shell:X})')
        print(f'  fcs = 0x{fcs:X} (anchor+0x{fcs-anchor:X})')

        # ---- PE header restore (import/resource from shell, TLS zero) ----
        # C# ref: pe+144 = info[6]+0x15E0, pe+148 = info[6]+0x15DC
        #         pe+152 = info[6]+0x1600, pe+156 = info[6]+0x1604
        # These are anchor-relative: anchor+0x08 = import_rva, anchor+0x04 = import_size
        # fcs-0x10 = resource_rva, fcs-0x0C = resource_size
        print('\n=== PE header restore ===')
        import_rva  = u32(data, anchor + 0x08)
        import_size = u32(data, anchor + 0x04)
        res_rva     = u32(data, fcs - 0x10)
        res_size    = u32(data, fcs - 0x0C)
        w32(data, pe_header + 144, import_rva)
        w32(data, pe_header + 148, import_size)
        w32(data, pe_header + 152, res_rva)
        w32(data, pe_header + 156, res_size)
        w32(data, pe_header + 176, 0)  # TLS RVA
        w32(data, pe_header + 180, 0)  # TLS Size
        print(f'  Import: RVA=0x{import_rva:X} Size=0x{import_size:X}')
        print(f'  Resource: RVA=0x{res_rva:X} Size=0x{res_size:X}')

        # ---- Checksums ----
        print('\n=== Computing checksums ===')
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

        # ---- Stage 3: SecondStage ----
        print('\n=== Stage 3: SecondStage ===')
        ss_pair = fcs + 0x40
        ss_key = (header_checksum ^ first_stage_cs ^ second_stage_key) & 0xFFFFFFFF
        decrypt_data3(data, ss_pair, ss_key, 21)
        ss = u32(data, ss_pair)
        ss_size = u32(data, ss_pair + 4)
        print(f'  secondStageStart = 0x{ss:08X}, size = 0x{ss_size:X}')

        # ---- SecondStage internal offsets ----
        # The SecondStage layout has variable-length regions:
        #   [code] [addresses] [keys(8B)] [zeros(12B)] [CS_pairs(32B)] [Kernel32.dll] [...]
        # Key/CS region and pair region can shift by different amounts across variants.
        #
        # Strategy: find "Kernel32.dll\0" string in SecondStage as anchor.
        # Keys are at anchor - 0x34, CS pairs at anchor - 0x20.
        # Pair offsets use a simple shift from baseline (ss_size - 0x10C8).
        pair_shift = ss_size - 0x10C8

        # Find "Kernel32.dll" anchor in SecondStage
        kernel32_pattern = b'Kernel32.dll\x00'
        kernel32_off = None
        for koff in range(0xD80, min(ss_size - 16, 0xF00)):
            if data[ss + koff : ss + koff + 13] == kernel32_pattern:
                kernel32_off = koff
                break
        if kernel32_off is not None:
            third_key_off  = kernel32_off - 0x34
            forth_key_off  = kernel32_off - 0x30
            second_cs_off  = kernel32_off - 0x20
            seven_cs_off   = kernel32_off - 0x18
            fifth_cs_off   = kernel32_off - 0x10
            forth_cs_off   = kernel32_off - 0x08
            key_shift = third_key_off - 0x0D74
            print(f'  Kernel32.dll at ss+0x{kernel32_off:X}, key_shift={key_shift:+d}, pair_shift={pair_shift:+d}')
        else:
            # Fallback: uniform shift
            key_shift = pair_shift
            third_key_off  = 0x0D74 + key_shift
            forth_key_off  = 0x0D78 + key_shift
            second_cs_off  = 0x0D88 + key_shift
            seven_cs_off   = 0x0D90 + key_shift
            fifth_cs_off   = 0x0D98 + key_shift
            forth_cs_off   = 0x0DA0 + key_shift
            print(f'  Kernel32.dll not found, using uniform shift={key_shift:+d}')

        # Stage pair offsets (EXE: DLL+8 because of extra pair at E38)
        third_pair_off = 0x0E30 + pair_shift
        forth_pair_off = 0x0E88 + pair_shift
        fifth_pair_off = 0x0E98 + pair_shift
        seven_pair_off = 0x0EB8 + pair_shift
        eighth_pair_off= 0x0F08 + pair_shift

        print(f'  thirdStageKey at ss+0x{third_key_off:X} = 0x{u32(data, ss + third_key_off):08X}')
        print(f'  forthStageKey at ss+0x{forth_key_off:X} = 0x{u32(data, ss + forth_key_off):08X}')

        # ---- Stage 4: ThirdStage ----
        print('\n=== Stage 4: ThirdStage ===')
        third_key = u32(data, ss + third_key_off)
        decrypt_data3(data, ss + third_pair_off, third_key, 19)
        ts = u32(data, ss + third_pair_off)
        ts_size = u32(data, ss + third_pair_off + 4)
        print(f'  thirdStageStart = 0x{ts:08X}, size = 0x{ts_size:X}')

        # ThirdStage internal offsets (C# DLL: keysAddr=ts+0x23C8, infoTable=ts+0x2420)
        # Auto-detect: scan for type=1/0x11 followed by type=2
        info_table = None
        keys_addr = None
        for off in range(0, ts_size - 32, 4):
            t0 = u32(data, ts + off)
            if t0 in (1, 0x11):
                t1 = u32(data, ts + off + 16)
                if t1 == 2:
                    addr0 = u32(data, ts + off + 4)
                    if 0x1000 < addr0 < len(data):
                        info_table = ts + off
                        keys_addr = info_table - 0x58
                        print(f'  infoTable at ts+0x{off:X} (abs 0x{info_table:X})')
                        print(f'  keysAddr at 0x{keys_addr:X}')
                        break
        if info_table is None:
            print('ERROR: cannot locate infoTable')
            return

        # ---- Process infoTable ----
        print('\n=== Processing infoTable ===')
        it_addr = info_table
        for j in range(2):
            tval = u32(data, it_addr)
            if tval in (1, 0x11):
                decrypt_data4(data, it_addr + 4)
            elif tval == 2:
                copy_addr = u32(data, it_addr + 4)
                while True:
                    decrypt_data5(data, copy_addr, 16)
                    s_a = u32(data, copy_addr)
                    s_sz = u32(data, copy_addr + 4)
                    d_a = u32(data, copy_addr + 8)
                    d_sz = u32(data, copy_addr + 12)
                    copy_addr += 16
                    if s_sz == 0:
                        break
                    if s_a != 0 and d_a != 0 and d_sz == s_sz:
                        print(f'    Copy: 0x{s_a:X}..0x{s_a+s_sz:X} -> 0x{d_a:X}..0x{d_a+s_sz:X} (size=0x{s_sz:X})')
                        data[d_a:d_a + s_sz] = data[s_a:s_a + s_sz]
                    elif s_sz != 0:
                        print(f'    Skip: src=0x{s_a:X} sSize=0x{s_sz:X} dst=0x{d_a:X} dSize=0x{d_sz:X}')
            it_addr += 16

        # ---- Extract keyOffsets ----
        print('\n=== Extracting keyOffsets ===')
        key_offsets = [0] * 4
        ka = keys_addr
        for k in range(2):
            ka2 = ka
            for l in range(2):
                decrypt_data4(data, ka2)
                key_offsets[k*2+l] = u32(data, ka2)
                ka2 += 8
            ka += 32
        for i, ko in enumerate(key_offsets):
            print(f'  keyOffsets[{i}] = 0x{ko:08X}')

        # ---- Checksum addresses ----
        print('\n=== Checksum addresses ===')
        second_stage_cs_addr = fcs - 0x08
        seven_stage_cs_addr  = ss + seven_cs_off
        fifth_stage_cs_addr  = ss + fifth_cs_off
        forth_stage_cs_addr  = ss + forth_cs_off

        # ---- Stage 5: ForthStage ----
        print('\n=== Stage 5: ForthStage ===')
        second_stage_cs = checksum_with_size_xor(data, second_stage_cs_addr)
        forth_stage_key = u32(data, ss + forth_key_off)
        forth_stage_key = advance_key(forth_stage_key, 4)
        fk = (header_checksum ^ second_stage_cs ^ forth_stage_key) & 0xFFFFFFFF
        forth_addr = ss + forth_pair_off
        forth_src = u32(data, forth_addr)
        forth_ssz = u32(data, forth_addr + 4)
        forth_dst = u32(data, forth_addr + 8)
        forth_dsz = u32(data, forth_addr + 12)
        print(f'  forthStage pair at 0x{forth_addr:X}: src=0x{forth_src:X} sSize=0x{forth_ssz:X} dst=0x{forth_dst:X} dSize=0x{forth_dsz:X}')
        print(f'  key = 0x{fk:08X}')
        decrypt_and_decompress(data, forth_addr, fk, key_offsets)

        # ---- Stage 6: FifthStage ----
        print('\n=== Stage 6: FifthStage ===')
        fifth_addr = ss + fifth_pair_off
        fifth_src = u32(data, fifth_addr)
        fifth_ssz = u32(data, fifth_addr + 4)
        fifth_dst_addr = u32(data, fifth_addr + 8)
        fifth_dsz_val = u32(data, fifth_addr + 12)
        print(f'  fifthStage pair at 0x{fifth_addr:X}: src=0x{fifth_src:X} sSize=0x{fifth_ssz:X} dst=0x{fifth_dst_addr:X} dSize=0x{fifth_dsz_val:X}')

        # C# ref line 678: forthStageCS pair at ss + 0xDA0
        forth_cs = checksum_with_size_xor(data, forth_stage_cs_addr)
        forth_region_off = u32(data, forth_stage_cs_addr)
        forth_region_sz  = u32(data, forth_stage_cs_addr + 4)
        fifth_key = u32(data, forth_region_off + forth_region_sz - 4)
        fk5 = (header_checksum ^ forth_cs ^ fifth_key) & 0xFFFFFFFF
        print(f'  forthCS pair: addr=0x{forth_region_off:X} size=0x{forth_region_sz:X}')
        print(f'  fifthKey from 0x{forth_region_off + forth_region_sz - 4:X} = 0x{fifth_key:08X}')
        print(f'  key = 0x{fk5:08X}')
        decrypt_and_decompress(data, fifth_addr, fk5, key_offsets)
        fifth_start_actual = u32(data, fifth_addr)

        # ---- Stage 7: SevenStage ----
        print('\n=== Stage 7: SevenStage ===')
        seven_addr = ss + seven_pair_off
        print(f'  sevenStage pair at 0x{seven_addr:X}')
        seven_src = u32(data, seven_addr)
        seven_ssz = u32(data, seven_addr + 4)
        seven_dst = u32(data, seven_addr + 8)
        seven_dsz = u32(data, seven_addr + 12)
        print(f'  seven pair: src=0x{seven_src:X} sSize=0x{seven_ssz:X} dst=0x{seven_dst:X} dSize=0x{seven_dsz:X}')

        fifth_cs = checksum_with_size_xor(data, fifth_stage_cs_addr)
        fifth_start_actual = u32(data, fifth_addr)
        fifth_dsz = u32(data, fifth_addr + 12)
        print(f'  fifthStart = 0x{fifth_start_actual:X}, fifthDsz = 0x{fifth_dsz:X}')

        # Try multiple sevenKey offsets by scanning fifthStage for valid key
        # Save backup of seven data for retry
        seven_backup = bytearray(data[seven_src:seven_src + seven_ssz])
        seven_pair_backup = bytearray(data[seven_addr:seven_addr + 16])

        # Build candidate list: scan the fifthStage for non-zero, non-ASCII 4-byte values
        seven_key_candidates = []
        # First try DLL offset and common heuristics
        for sk_off in [0x7B0, 0x7A8, 0x7A0, 0x798]:
            if sk_off + 4 <= fifth_dsz:
                seven_key_candidates.append(sk_off)
        # Then scan last 0x200 bytes of fifthStage for non-trivial values
        for sk_off in range(max(0, fifth_dsz - 0x200), fifth_dsz - 4, 4):
            if sk_off not in seven_key_candidates:
                val = u32(data, fifth_start_actual + sk_off)
                # Skip zeros and obvious strings (ASCII-like)
                if val != 0 and val != 0xCCCCCCCC and not all(32 <= ((val >> (i*8)) & 0xFF) < 127 for i in range(4)):
                    seven_key_candidates.append(sk_off)

        seven_success = False
        for sk_off in seven_key_candidates:
            # Restore seven data
            data[seven_src:seven_src + seven_ssz] = seven_backup[:]
            data[seven_addr:seven_addr + 16] = seven_pair_backup[:]

            seven_key = (~u32(data, fifth_start_actual + sk_off)) & 0xFFFFFFFF
            fk7 = (header_checksum ^ fifth_cs ^ seven_key) & 0xFFFFFFFF

            # Try decrypt (silent)
            try:
                result = decrypt_and_decompress(data, seven_addr, fk7, key_offsets, verbose=False)
                if result:
                    seven_result = u32(data, seven_addr)
                    if 0x1000 < seven_result < len(data):
                        print(f'  SUCCESS: sevenKey at fifth+0x{sk_off:X}, val=0x{u32(data, fifth_start_actual + sk_off):08X}')
                        print(f'  sevenStageStart = 0x{seven_result:X}, key = 0x{fk7:08X}')
                        seven_success = True
                        break
            except Exception as e:
                pass

        if not seven_success:
            print('ERROR: could not decrypt sevenStage with any key offset')
            return

        # ---- Stage 8: EighthStage ----
        print('\n=== Stage 8: EighthStage ===')
        seven_start_actual = u32(data, seven_addr)

        # Find customDecryptor by scanning sevenStage for LFSR block (backward from end)
        # C# DLL uses fixed offset 0xC80, but EXE may differ
        scan_start = max(0, seven_dsz // 2)
        custom_dec_off = find_lfsr_block(data, seven_start_actual, seven_dsz, scan_start, scan_backward=True)
        if custom_dec_off is None:
            # Try forward from beginning
            custom_dec_off = find_lfsr_block(data, seven_start_actual, seven_dsz, 0)
        if custom_dec_off is None:
            print('ERROR: could not locate customDecryptor in sevenStage')
            return
        custom_dec_addr = seven_start_actual + custom_dec_off
        print(f'  customDecryptor at seven+0x{custom_dec_off:X}')
        decrypt_data6(data, custom_dec_addr)
        custom_dec = generate_custom_decryptor(data, custom_dec_addr)
        if custom_dec is None:
            print('ERROR: failed to generate custom decryptor')
            return
        print(f'  customDecryptor generated OK')

        # C# ref line 704: sevenStageChecksum at ss + 0xD90
        seven_cs = checksum_with_size_xor(data, seven_stage_cs_addr)

        # eighthStageKey: in C# DLL it's at sevenStart + 0xC58 (= customDecryptor - 0x28)
        # For EXE the gap may differ. Search data block before API strings.
        # Save backup for brute-force
        eighth_addr_pair = ss + eighth_pair_off
        eighth_src = u32(data, eighth_addr_pair)
        eighth_ssz = u32(data, eighth_addr_pair + 4)
        eighth_backup = bytearray(data[eighth_src:eighth_src + eighth_ssz])
        eighth_pair_bak = bytearray(data[eighth_addr_pair:eighth_addr_pair + 16])

        # Try different gaps from customDecryptor
        eighth_key_success = False
        eighth_key_candidates = []
        # Try gaps: 0x28 (DLL), 0x50, 0x48, 0x30, and scan data block
        for gap in [0x28, 0x50, 0x48, 0x30, 0x40, 0x58, 0x60, 0x20, 0x38]:
            off = custom_dec_off - gap
            if off >= 0 and off + 4 <= seven_dsz:
                val = u32(data, seven_start_actual + off)
                if val != 0 and val != 0xCCCCCCCC:
                    eighth_key_candidates.append(off)
        # Also scan the region before customDecryptor for non-zero, non-string values
        for off in range(max(0, custom_dec_off - 0x100), custom_dec_off, 4):
            if off not in eighth_key_candidates:
                val = u32(data, seven_start_actual + off)
                if val != 0 and val != 0xCCCCCCCC and not all(32 <= ((val >> (i*8)) & 0xFF) < 127 for i in range(4)):
                    eighth_key_candidates.append(off)

        for ek_off in eighth_key_candidates:
            # Restore
            data[eighth_src:eighth_src + eighth_ssz] = eighth_backup[:]
            data[eighth_addr_pair:eighth_addr_pair + 16] = eighth_pair_bak[:]

            test_key = u32(data, seven_start_actual + ek_off)
            test_key = advance_key(test_key, 3)
            fk8 = (header_checksum ^ fifth_cs ^ seven_cs ^ test_key) & 0xFFFFFFFF

            try:
                result = decrypt_and_decompress(data, eighth_addr_pair, fk8, key_offsets, custom_dec, verbose=False)
                if result:
                    eighth_start_test = u32(data, eighth_addr_pair)
                    if 0x1000 < eighth_start_test < len(data):
                        eighth_key = test_key
                        print(f'  eighthStageKey at seven+0x{ek_off:X}, raw=0x{u32(data, seven_start_actual + ek_off):08X}')
                        print(f'  eighthStage pair at 0x{eighth_addr_pair:X}, key = 0x{fk8:08X}')
                        eighth_key_success = True
                        break
            except:
                pass

        if not eighth_key_success:
            print('ERROR: could not find valid eighthStageKey')
            return

        eighth_start = u32(data, eighth_addr_pair)
        print(f'  eighthStageStart = 0x{eighth_start:08X}')

        # ============================================================
        # Final processing (PE32+ path)
        # ============================================================
        print('\n=== Final: File data decryption ===')

        eighth_dsz = u32(data, eighth_addr_pair + 12)
        print(f'  eighthDsz = 0x{eighth_dsz:X}')

        # Strategy: find file LFSR decryptor first (most distinctive feature),
        # then derive fileCS and other offsets from its position.
        # C# DLL ref: fileDecryptorAddress = fileChecksumAddresses + 0x58
        #   importTable at eighthStart+0x2EF0
        #   compressedInfo at eighthStart+0x2EC8  (= importTable - 0x28)
        #   fileCS at eighthStart+0x3018          (= importTable + 0x128)
        #   fileLFSR at fileCS+0x58               (= eighthStart+0x3070)

        # Collect ALL LFSR candidates (forward scan)
        all_lfsrs = []
        scan_off = 0
        while scan_off < eighth_dsz - 95:
            found = find_lfsr_block(data, eighth_start, eighth_dsz, start_off=scan_off)
            if found is None:
                break
            all_lfsrs.append(found)
            scan_off = found + 96

        # Find the correct file LFSR: scan backward, validate LFSR-0x58 has a valid pointer
        off_file_lfsr = None
        for lfsr_off in reversed(all_lfsrs):
            cs_off = lfsr_off - 0x58
            if cs_off >= 0:
                cs_val = u32(data, eighth_start + cs_off)
                if 0x1000 < cs_val < len(data):
                    off_file_lfsr = lfsr_off
                    print(f'  fileLFSR at eighth+0x{lfsr_off:X} (fileCS at +0x{cs_off:X} -> 0x{cs_val:08X})')
                    break
        if off_file_lfsr is None:
            print('ERROR: could not locate file LFSR in eighthStage')
            return

        # Derive fileCS (C# ref: fileDecryptorAddress = fileChecksumAddresses + 0x58)
        off_file_cs = off_file_lfsr - 0x58
        file_cs_ptr_addr = eighth_start + off_file_cs
        file_cs_addr = u32(data, file_cs_ptr_addr)
        print(f'  fileCS at eighth+0x{off_file_cs:X}, ptr -> 0x{file_cs_addr:08X}')

        if file_cs_addr == 0 or file_cs_addr >= len(data) - 8:
            print('ERROR: fileCS pointer is invalid')
            return

        # Search for compressedInfo and importTable
        # Strategy: find the anchor, collect all valid pointer values in the data area,
        # then identify compressedInfo by trial-decrypting the first entry.
        off_import_table = None
        off_compressed_info = None

        # Compute compress_data_offset early for validation
        compress_data_offset = ((~u32(file_data, 0x1080)) & 0xFFFFFFFF) + 0x1000
        file_data_len = len(file_data)

        # Find anchor "pm\x00\x00cm\x00\x00"
        anchor_off = None
        for aoff in range(eighth_dsz - 8, 0, -1):
            if data[eighth_start + aoff:eighth_start + aoff + 8] == b'pm\x00\x00cm\x00\x00':
                anchor_off = aoff
                break
        if anchor_off:
            print(f'  anchor "pm..cm.." at eighth+0x{anchor_off:X}')

        # Collect all valid pointer values in the data area (from anchor to LFSR)
        scan_from = anchor_off if anchor_off else max(off_file_lfsr - 0x400, 0)
        all_ptrs = []
        for doff in range(scan_from, off_file_lfsr, 4):
            val = u32(data, eighth_start + doff)
            if 0x10000 < val < len(data) - 16:
                all_ptrs.append((doff, val))

        # Trial-decrypt to find compressedInfo: the pointer whose data,
        # after DecryptData5, gives reasonable (src, sSize, dst, dSize)
        compress_candidates = []
        for doff, ptr_val in all_ptrs:
            if doff == off_file_cs:
                continue  # Skip fileCS
            # Save 16 bytes at the pointed address
            backup = bytes(data[ptr_val:ptr_val + 16])
            decrypt_data5(data, ptr_val, 16)
            src2 = u32(data, ptr_val)
            s_sz2 = u32(data, ptr_val + 4)
            dst2 = u32(data, ptr_val + 8)
            d_sz2 = u32(data, ptr_val + 12)
            # Restore
            data[ptr_val:ptr_val + 16] = backup
            # Validate: compressedDataInfo entry should have reasonable values
            src_file_off = src2 + compress_data_offset
            valid = (s_sz2 > 0 and s_sz2 < 0x200000 and
                     src_file_off + s_sz2 <= file_data_len and
                     dst2 >= 0x1000 and dst2 + d_sz2 <= len(data) and
                     d_sz2 >= s_sz2 and d_sz2 < 0x200000)
            if valid:
                compress_candidates.append((doff, ptr_val))

        if compress_candidates:
            off_compressed_info = compress_candidates[0][0]
            print(f'  compressedInfo at eighth+0x{off_compressed_info:X}, ptr -> 0x{u32(data, eighth_start + off_compressed_info):08X}')
        else:
            print('ERROR: could not locate compressedInfo in eighthStage')
            return

        # importTable: search all pointer values for one pointing to zeros/empty IDT area
        # (the IDT is populated AFTER file decompression, so currently it may be zeros)
        for doff, ptr_val in all_ptrs:
            if doff == off_file_cs or doff == off_compressed_info:
                continue
            # Check if the pointed area has zeros (IDT not yet populated)
            first8 = u64(data, ptr_val) if ptr_val + 8 <= len(data) else 1
            if first8 == 0:
                off_import_table = doff
                print(f'  importTable at eighth+0x{off_import_table:X}, ptr -> 0x{u32(data, eighth_start + off_import_table):08X} (zeros = IDT not yet populated)')
                break

        if off_import_table is None:
            print('  WARNING: importTable not found yet, will search after file decompression')

        # ---- Process file checksums ----
        file_cs_addr_ptr = eighth_start + off_file_cs
        file_cs_addr = u32(data, file_cs_addr_ptr)
        print(f'  fileChecksumAddr = 0x{file_cs_addr:08X}')
        while u32(data, file_cs_addr + 4) != 0:
            decrypt_data5(data, file_cs_addr, 16)
            file_cs_addr += 16

        # ---- Generate file decryptor ----
        file_dec_addr = eighth_start + off_file_lfsr
        decrypt_data6(data, file_dec_addr)
        file_dec = generate_custom_decryptor(data, file_dec_addr)
        if file_dec is None:
            print('ERROR: failed to generate file decryptor')
            return

        # ---- Decompress file data blocks ----
        clean_file_data = bytearray(open(in_file, 'rb').read())
        # compress_data_offset already computed above

        # Save metadata before decompression for corruption detection
        meta_before = bytes(data[info[3]:info[3] + 0x100])

        compressed_info_addr = eighth_start + off_compressed_info
        compressed_info = u32(data, compressed_info_addr)
        print(f'  compressDataOffset = 0x{compress_data_offset:X}')
        print(f'  compressedDataInfo = 0x{compressed_info:08X}')

        block_count = 0
        decomp_ranges = []
        while True:
            decrypt_data5(data, compressed_info, 16)
            src2  = u32(data, compressed_info)
            s_sz2 = u32(data, compressed_info + 4)
            dst2  = u32(data, compressed_info + 8)
            d_sz2 = u32(data, compressed_info + 12)
            compressed_info += 16
            if s_sz2 == 0:
                break
            decomp_ranges.append((dst2, d_sz2))
            file_src = src2 + compress_data_offset
            data[dst2:dst2 + s_sz2] = clean_file_data[file_src:file_src + s_sz2]
            aes_decrypt(data, dst2, s_sz2, key_offsets[2])
            _lut, _tt = file_dec
            data[dst2:dst2 + s_sz2] = bytearray(bytes(data[dst2:dst2 + s_sz2]).translate(_tt))
            if s_sz2 != d_sz2:
                decompress(data, dst2, dst2, key_offsets[0], s_sz2, d_sz2)
            block_count += 1
        print(f'  Decrypted {block_count} data blocks')
        # Print decompression coverage
        decomp_ranges.sort()
        total_decomp = sum(d for _,d in decomp_ranges)
        print(f'  Decompression blocks: {len(decomp_ranges)}, total size: 0x{total_decomp:X}')
        for dst, dsz in decomp_ranges[:5]:
            print(f'    0x{dst:X} - 0x{dst+dsz:X} (0x{dsz:X})')
        if len(decomp_ranges) > 5:
            print(f'    ... ({len(decomp_ranges) - 5} more)')
            for dst, dsz in decomp_ranges[-2:]:
                print(f'    0x{dst:X} - 0x{dst+dsz:X} (0x{dsz:X})')

        # Check if file decompression corrupted metadata area
        meta_after = bytes(data[info[3]:info[3] + 0x100])
        if meta_before != meta_after:
            changed = sum(1 for a,b in zip(meta_before, meta_after) if a != b)
            print(f'  WARNING: metadata at info[3]=0x{info[3]:X} changed by decompression ({changed} bytes differ)')
        else:
            print(f'  Metadata at info[3]=0x{info[3]:X} NOT affected by decompression')

        # ---- Zero-out list (C# DLL: runs AFTER file decompression) ----
        zero_count = 0
        zero_ranges = []
        while True:
            decrypt_data5(data, compressed_info, 16)
            src3  = u32(data, compressed_info)
            s_sz3 = u32(data, compressed_info + 4)
            compressed_info += 16
            if s_sz3 == 0:
                break
            zero_ranges.append((src3, s_sz3))
            data[src3:src3 + s_sz3] = b'\x00' * s_sz3
            zero_count += 1
        print(f'  Zeroed {zero_count} regions')
        for zr, zs in zero_ranges[:5]:
            print(f'    0x{zr:X} - 0x{zr+zs:X} (0x{zs:X})')
        if len(zero_ranges) > 5:
            print(f'    ... ({len(zero_ranges)-5} more)')

        # ---- Import table reconstruction (C# DLL reference) ----
        print('\n=== Import table reconstruction ===')

        # Get the original import directory RVA from metadata at info[3]
        # The metadata is encrypted with DecryptData5 and contains the original PE data dirs
        # Layout B: decrypt info[3]+0x10, data dirs at info[3]+0x30
        # Layout A: decrypt info[3]+0x40, data dirs at info[3]+0x50
        import_table_ptr = 0
        test_val = u32(data, info[3] + 0x10)
        is_layout_a = (test_val <= 0x10000)
        if test_val > 0x10000:
            # Layout B: peek at info[3]+0x38 (import dir = second data directory)
            backup_meta = bytes(data[info[3] + 0x10:info[3] + 0x10 + 0x30])
            decrypt_data5(data, info[3] + 0x10, 0x30)
            import_table_ptr = u32(data, info[3] + 0x38)
            data[info[3] + 0x10:info[3] + 0x10 + 0x30] = backup_meta
            print(f'  Layout B: original import RVA = 0x{import_table_ptr:X}')
        else:
            # Layout A: peek at info[3]+0x58
            backup_meta = bytes(data[info[3] + 0x40:info[3] + 0x40 + 0x20])
            decrypt_data5(data, info[3] + 0x40, 0x20)
            import_table_ptr = u32(data, info[3] + 0x58)
            peeked_ep = u32(data, info[3] + 0x40)
            data[info[3] + 0x40:info[3] + 0x40 + 0x20] = backup_meta
            print(f'  Layout A: original import RVA = 0x{import_table_ptr:X}, EP = 0x{peeked_ep:X}')

        # Validate
        if import_table_ptr > 0 and import_table_ptr + 20 <= len(data):
            test_name = u32(data, import_table_ptr + 12)
            if test_name == 0 or test_name >= len(data):
                print(f'  WARNING: importTableBase 0x{import_table_ptr:X} has invalid name RVA 0x{test_name:X}')
                import_table_ptr = 0

        # If importTable was found in the eighthStage data area as fallback
        if import_table_ptr == 0 and off_import_table is not None:
            import_table_ptr = u32(data, eighth_start + off_import_table)
            test_name = u32(data, import_table_ptr + 12) if import_table_ptr + 20 <= len(data) else 0
            if test_name == 0 or test_name >= len(data):
                import_table_ptr = 0

        if import_table_ptr == 0:
            print('  WARNING: Could not find import table, skipping import reconstruction')
        else:
            print(f'  importTableBase = 0x{import_table_ptr:X}')

        # Walk IDT and decrypt DLL/function names (like C# DLL reference)
        # PE32+: 8-byte thunks (same as C# DLL which uses thunk += 8)
        dll_count = 0
        if import_table_ptr > 0:
            idt_pos = import_table_ptr
            while True:
                name_rva = u32(data, idt_pos + 12)
                if name_rva == 0:
                    break
                if name_rva >= len(data):
                    print(f'  WARNING: name_rva 0x{name_rva:X} out of range, stopping IDT walk')
                    break
                # Decrypt DLL name
                decrypt_data7(data, name_rva, name_rva & 0xFF)
                dll_name = get_string(data, name_rva)

                # Get thunk table (prefer OriginalFirstThunk, fallback to FirstThunk)
                orig_first_thunk = u32(data, idt_pos)
                first_thunk = u32(data, idt_pos + 16)
                thunk = orig_first_thunk if orig_first_thunk != 0 else first_thunk

                func_count = 0
                while True:
                    if thunk + 8 > len(data):
                        break
                    # PE32+: 8-byte thunk entries
                    func_name_rva = u64(data, thunk)
                    if func_name_rva == 0:
                        break
                    if not (func_name_rva & 0x8000000000000000):
                        # By name, not ordinal
                        rva32 = func_name_rva & 0xFFFFFFFF
                        if rva32 + 2 < len(data):
                            decrypt_data7(data, rva32 + 2, rva32 & 0xFF)
                            w16(data, rva32, 0)  # clear hint
                    thunk += 8
                    func_count += 1
                print(f'  DLL: {dll_name} ({func_count} functions)')
                dll_count += 1
                idt_pos += 20
        print(f'  Total: {dll_count} DLLs')

        # ---- Section table fixup ----
        print('\n=== Section table fixup ===')
        data[:0x1000] = file_data[:0x1000]
        opt_hdr_size = u16(file_data, pe_header + 20)
        sec_hdr = pe_header + 24 + opt_hdr_size

        export_va   = u32(clean_file_data, pe_header + 24 + opt_hdr_size - 128)
        export_size = u32(clean_file_data, pe_header + 24 + opt_hdr_size - 124)
        export_file_off = 0
        text_off = 0
        text_size = 0

        while u32(file_data, sec_hdr + 8) != 0:
            va   = u32(file_data, sec_hdr + 12)
            sz   = u32(file_data, sec_hdr + 8)
            f_off = u32(file_data, sec_hdr + 20)
            sec_name = file_data[sec_hdr:sec_hdr + 8]
            if sec_name[:5] == b'.text':
                text_size = sz
                text_off = va
            if export_va >= va and export_va + export_size <= va + sz:
                export_file_off = export_va - va + f_off
            # Fix SizeOfRawData = VirtualSize, PointerToRawData = VirtualAddress
            w32(data, sec_hdr + 16, sz)
            w32(data, sec_hdr + 20, va)
            # .rdata needs RW for IAT (loader writes resolved addresses)
            if sec_name[:6] == b'.rdata':
                w32(data, sec_hdr + 36, 0xC0000040)  # MEM_READ | MEM_WRITE | CNT_INITIALIZED_DATA
            # Do NOT modify section characteristics (reference C# doesn't)
            sec_hdr += 40

        if export_size != 0 and export_file_off != 0:
            data[export_va:export_va + export_size] = file_data[export_file_off:export_file_off + export_size]
            print(f'  Restored export table at 0x{export_va:X}')

        # ---- Decrypt .text section with decrypt_data8 (auto-detect key formula) ----
        # CrackProof encrypts .text per-page with decrypt_data8, but different versions
        # use different key formulas:
        #   Formula A: key = page + 1  (newer CrackProof versions)
        #   Formula B: key = 0x8000 * (page + 1)  (older CrackProof versions)
        # Auto-detect: try each formula on the EP page, check if EP call target becomes
        # a valid function prologue (sub rsp, XX pattern).
        if is_layout_a and text_size > 0 and text_off > 0:
            def apply_page_decrypt_data8(buf, t_off, page_idx, key_formula):
                """Apply decrypt_data8 to a single page"""
                pk = key_formula(page_idx)
                pa = t_off + page_idx * 0x1000
                k = pk
                rk = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
                k = rk
                for bi in range(1, 256):
                    rk = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
                    ri = (rk + bi) & 0xFFFFFFFF
                    k = (ri + bi) & 0xFFFFFFFF
                    tidx = pa + bi * 16 + (ri & 0xF)
                    buf[tidx] = (buf[tidx] ^ k) & 0xFF

            def apply_full_text_decrypt_data8(buf, t_off, t_size, key_formula):
                """Apply decrypt_data8 to entire .text"""
                n_pages = t_size // 0x1000
                for pg in range(n_pages):
                    apply_page_decrypt_data8(buf, t_off, pg, key_formula)

            def check_ep_quality(buf, ep_addr):
                """Check if EP and its call target look like valid code. Returns score."""
                if ep_addr + 10 > len(buf):
                    return -1
                score = 0
                # Check EP prologue: sub rsp, 0x28; call rel32
                if buf[ep_addr:ep_addr+4] == bytes([0x48, 0x83, 0xEC, 0x28]) and buf[ep_addr+4] == 0xE8:
                    score += 10
                    # Check call target
                    rel32 = struct.unpack_from('<i', buf, ep_addr + 5)[0]
                    ct = ep_addr + 9 + rel32
                    if 0 < ct < len(buf) - 16:
                        # Check if call target has sub rsp pattern: 48 83 EC XX
                        for off in range(min(16, len(buf) - ct - 4)):
                            if buf[ct+off] == 0x48 and buf[ct+off+1] == 0x83 and buf[ct+off+2] == 0xEC:
                                score += 20
                                break
                        # Also accept: 48 89 5C ... pattern (common prologue)
                        if buf[ct] == 0x48 and buf[ct+1] == 0x89:
                            score += 5
                return score

            # Determine which pages to test (EP page + call target page)
            ep_page = (peeked_ep - text_off) // 0x1000 if peeked_ep >= text_off else 0
            test_pages = {ep_page}
            # Also find call target page
            if peeked_ep + 9 <= len(data) and data[peeked_ep + 4] == 0xE8:
                rel32 = struct.unpack_from('<i', data, peeked_ep + 5)[0]
                ct = peeked_ep + 9 + rel32
                if ct >= text_off and ct < text_off + text_size:
                    test_pages.add((ct - text_off) // 0x1000)

            # Test three options on just the test pages
            formulas = [
                ('none', None),
                ('page+1', lambda p: p + 1),
                ('0x8000*(page+1)', lambda p: 0x8000 * (p + 1)),
            ]
            best_score = -1
            best_name = 'none'
            best_formula = None

            for fname, ffunc in formulas:
                test_buf = bytearray(data)
                if ffunc is not None:
                    for pg in test_pages:
                        apply_page_decrypt_data8(test_buf, text_off, pg, ffunc)
                sc = check_ep_quality(test_buf, peeked_ep)
                print(f'  decrypt_data8 {fname}: EP quality score = {sc}')
                if sc > best_score:
                    best_score = sc
                    best_name = fname
                    best_formula = ffunc

            if best_formula is not None:
                print(f'\n=== Decrypting .text with decrypt_data8 (key={best_name}) ===')
                apply_full_text_decrypt_data8(data, text_off, text_size, best_formula)
                num_pages = text_size // 0x1000
                print(f'  Decrypted {num_pages} pages')
            else:
                print(f'  .text already decrypted (best option: no decrypt_data8)')

        # ---- Metadata restore: EP + data directories from info[3] ----
        # C# DLL ref: DecryptData5(info[3] + 16, 0x290)
        #             EP = info[3] + 0x20
        #             Data dirs: copy 0x80 bytes from info[3]+0x30 to pe+0x88
        # For EXE: auto-detect Layout A vs B
        #   Layout B (encrypted at +0x10): decrypt(info[3]+0x10, 0x290), EP at +0x20, dirs at +0x30
        #   Layout A (plain at +0x10): decrypt(info[3]+0x40, 144), EP at +0x40, dirs at +0x50
        print('\n=== Metadata restore ===')
        exe_pe = u32(data, 60)
        test_val = u32(data, info[3] + 0x10)

        # Decrypt metadata and restore EP + data directories
        if test_val > 0x10000:
            # Layout B: decrypt info[3]+0x10 (0x290 bytes), EP at +0x20, dirs at +0x30
            # Layout B metadata data directories are reliable - copy them
            print(f'  Layout B: decrypting metadata at info[3]+0x10')
            decrypt_data5(data, info[3] + 0x10, 0x290)
            original_ep = u32(data, info[3] + 0x20)
            for i in range(128):
                data[exe_pe + 0x88 + i] = data[info[3] + 0x30 + i]
        else:
            # Layout A: decrypt info[3]+0x40 (144 bytes), EP at +0x40
            print(f'  Layout A: decrypting metadata at info[3]+0x40')
            decrypt_data5(data, info[3] + 0x40, 144)
            original_ep = u32(data, info[3] + 0x40)
            # Compare metadata data dirs with protected file PE header
            dirs_name = ['Export','Import','Resource','Exception','Security','BaseReloc','Debug','Arch','GlobPtr','TLS','LoadCfg','BoundImp','IAT','DelayImp','CLR','Rsv']
            for di in range(16):
                meta_rva = u32(data, info[3] + 0x50 + di*8)
                meta_sz  = u32(data, info[3] + 0x50 + di*8 + 4)
                pe_rva   = u32(data, exe_pe + 0x88 + di*8)
                pe_sz    = u32(data, exe_pe + 0x88 + di*8 + 4)
                if meta_rva != pe_rva or meta_sz != pe_sz:
                    print(f'  {dirs_name[di]}: PE=0x{pe_rva:X}/{pe_sz:X} META=0x{meta_rva:X}/{meta_sz:X}')
            # Copy data dirs from metadata
            for i in range(128):
                data[exe_pe + 0x88 + i] = data[info[3] + 0x50 + i]

        # Set entry point
        w32(data, exe_pe + 40, original_ep)
        print(f'  Entry point set to 0x{original_ep:X}')

        # ALWAYS set import directory to the reconstructed IDT location
        if import_table_ptr > 0 and import_table_ptr < len(data):
            w32(data, exe_pe + 0x90, import_table_ptr)
            idt_count = 0
            iat_min = 0xFFFFFFFF
            iat_max = 0
            pos = import_table_ptr
            while pos + 20 <= len(data):
                if u32(data, pos + 12) == 0:
                    break
                first_thunk = u32(data, pos + 16)
                if first_thunk > 0 and first_thunk < len(data):
                    if first_thunk < iat_min:
                        iat_min = first_thunk
                    # Walk thunks to find end
                    tp = first_thunk
                    while tp + 8 <= len(data):
                        tv = u64(data, tp)
                        if tv == 0:
                            tp += 8
                            break
                        tp += 8
                    if tp > iat_max:
                        iat_max = tp
                idt_count += 1
                pos += 20
            import_size = (idt_count + 1) * 20
            w32(data, exe_pe + 0x94, import_size)
            print(f'  Import directory: RVA=0x{import_table_ptr:X} Size=0x{import_size:X} ({idt_count} DLLs)')

            # Set IAT data directory from FirstThunk ranges
            if iat_min < iat_max:
                w32(data, exe_pe + 0xE8, iat_min)
                w32(data, exe_pe + 0xEC, iat_max - iat_min)
                print(f'  IAT directory: RVA=0x{iat_min:X} Size=0x{iat_max - iat_min:X}')

        # Fix PE header fields (match old working script)
        w16(data, exe_pe + 92, 3)   # Subsystem = CUI
        w16(data, exe_pe + 94, 0)   # DllCharacteristics = 0
        print(f'  Set Subsystem=3 (CUI), DllCharacteristics=0')

        # Zero out BaseReloc directory
        w32(data, exe_pe + 0xB0, 0)
        w32(data, exe_pe + 0xB4, 0)

        # ---- Write output ----
        dot = in_file.rfind('.')
        if dot >= 0:
            out_file = in_file[:dot] + '.unpack' + in_file[dot:]
        else:
            out_file = in_file + '.unpack'
        print(f'\n=== Writing {out_file} ===')
        with open(out_file, 'wb') as f:
            f.write(data)
        print(f'Done! {_elapsed()}')
        return

    # ============================================================
    # PE32 (32-bit) processing
    # ============================================================
    print('\n=== Locating shell offsets (PE32) ===')
    tbl = find_tbl(data, info)
    if tbl is None:
        print('ERROR: cannot locate tbl in shell')
        return
    print(f'  tbl = 0x{tbl:X}')

    # PE header restore
    print('\n=== PE header restore ===')
    val_bc = u32(data, tbl + 0xBC)
    val_c8 = u32(data, tbl + 0xC8)
    val_cc = u32(data, tbl + 0xCC)
    w32(data, pe_header + 0x80, val_bc)
    w32(data, pe_header + 0x88, val_c8)
    w32(data, pe_header + 0x8C, val_cc)
    w32(data, pe_header + 0xB0, 0)
    w32(data, pe_header + 0xB4, 0)

    # Checksums
    print('\n=== Computing checksums ===')
    hcs_addr = tbl + 0x58
    header_checksum = 0
    while u32(data, hcs_addr + 4) != 0:
        pa = u32(data, hcs_addr)
        ps = u32(data, hcs_addr + 4)
        header_checksum ^= (crc32(data, pa, ps) ^ ps)
        hcs_addr += 8
    first_stage_cs = checksum_with_size_xor(data, tbl + 0xA8)
    second_stage_key = u32(data, tbl + 0x40)
    print(f'  headerChecksum = 0x{header_checksum:08X}')

    # SecondStage
    print('\n=== Stage 3: SecondStage ===')
    ss_pair = tbl + 0x98
    ss_key = (header_checksum ^ first_stage_cs ^ second_stage_key) & 0xFFFFFFFF
    decrypt_data3(data, ss_pair, ss_key, 21)
    ss = u32(data, ss_pair)
    ss_size = u32(data, ss_pair + 4)
    print(f'  secondStageStart = 0x{ss:08X}, size = 0x{ss_size:X}')

    ss_shift = ss_size - 0xBC0
    if ss_shift not in (0, 0x10):
        print(f'WARNING: unexpected ss_size 0x{ss_size:X}')

    # PE32 fixed offsets
    third_key_off = 0x968 + ss_shift
    forth_key_off = 0x964 + ss_shift
    cs_base_off = 0x96C + ss_shift
    dp_base_off = 0xA9C + ss_shift

    # ThirdStage
    print('\n=== Stage 4: ThirdStage ===')
    third_pair_off = 0xB8C + ss_shift
    ts, ts_size = None, None

    # try_decrypt_third_stage (PE32, in-place)
    key = u32(data, ss + third_key_off)
    pair_addr = ss + third_pair_off
    ts_addr = u32(data, pair_addr)
    ts_size_raw = u32(data, pair_addr + 4)
    backup = bytearray(data[ts_addr:ts_addr + ts_size_raw])
    for shift in (19, 21, 17, 23, 15, 25, 13, 11):
        data[ts_addr:ts_addr + ts_size_raw] = backup[:]
        w32(data, pair_addr, ts_addr)
        w32(data, pair_addr + 4, ts_size_raw)
        decrypt_data3(data, pair_addr, key, shift)
        # Scan for infoTable
        for off in range(0, ts_size_raw - 32, 4):
            t0 = u32(data, ts_addr + off)
            if t0 in (1, 0x11):
                t1 = u32(data, ts_addr + off + 16)
                if t1 == 2:
                    addr0 = u32(data, ts_addr + off + 4)
                    if 0x1000 < addr0 < len(data):
                        info_table = ts_addr + off
                        keys_addr = info_table - 0x58
                        ts = ts_addr
                        ts_size = ts_size_raw
                        print(f'  thirdStage decrypted with shift={shift}, start=0x{ts:X}')
                        break
            if ts is not None:
                break
        if ts is not None:
            break
    if ts is None:
        print('ERROR: cannot decrypt thirdStage')
        return

    # Process infoTable
    it_addr = info_table
    for j in range(2):
        tval = u32(data, it_addr)
        if tval in (1, 0x11):
            decrypt_data4(data, it_addr + 4)
        elif tval == 2:
            copy_addr = u32(data, it_addr + 4)
            while True:
                decrypt_data5(data, copy_addr, 16)
                s_a = u32(data, copy_addr)
                s_sz = u32(data, copy_addr + 4)
                d_a = u32(data, copy_addr + 8)
                d_sz = u32(data, copy_addr + 12)
                copy_addr += 16
                if s_sz == 0: break
                if s_a != 0 and d_a != 0 and d_sz == s_sz:
                    data[d_a:d_a + s_sz] = data[s_a:s_a + s_sz]
        it_addr += 16

    # keyOffsets
    key_offsets = [0] * 4
    ka = keys_addr
    for k in range(2):
        ka2 = ka
        for l in range(2):
            decrypt_data4(data, ka2)
            key_offsets[k*2+l] = u32(data, ka2)
            ka2 += 8
        ka += 32

    # Checksum addresses (PE32)
    second_stage_cs_addr = tbl + 0xB0
    forth_stage_cs_addr  = ss + cs_base_off
    fifth_stage_cs_addr  = ss + cs_base_off + 0x08
    seven_stage_cs_addr  = ss + cs_base_off + 0x10

    # ForthStage
    second_stage_cs = checksum_with_size_xor(data, second_stage_cs_addr)
    forth_stage_key = u32(data, ss + forth_key_off)
    forth_stage_key = advance_key(forth_stage_key, 4)
    dp_base = ss + dp_base_off
    forth_addr = dp_base + 0x40
    fk = (header_checksum ^ second_stage_cs ^ forth_stage_key) & 0xFFFFFFFF
    decrypt_and_decompress(data, forth_addr, fk, key_offsets)

    # FifthStage
    fifth_addr = dp_base + 0x50
    forth_cs = checksum_with_size_xor(data, forth_stage_cs_addr)
    forth_region_off = u32(data, forth_stage_cs_addr)
    forth_region_sz  = u32(data, forth_stage_cs_addr + 4)
    fifth_key = u32(data, forth_region_off + forth_region_sz - 4)
    fk5 = (header_checksum ^ forth_cs ^ fifth_key) & 0xFFFFFFFF
    decrypt_and_decompress(data, fifth_addr, fk5, key_offsets)

    # SevenStage
    seven_addr = dp_base + 0x70
    seven_dsz = u32(data, seven_addr + 12)
    fifth_cs = checksum_with_size_xor(data, fifth_stage_cs_addr)
    cs1_off = cs_base_off + 0x08
    cs1_addr = u32(data, ss + cs1_off)
    cs1_size = u32(data, ss + cs1_off + 4)
    seven_key = (~u32(data, cs1_addr + cs1_size - 0x10)) & 0xFFFFFFFF
    fk7 = (header_checksum ^ fifth_cs ^ seven_key) & 0xFFFFFFFF
    decrypt_and_decompress(data, seven_addr, fk7, key_offsets)

    # EighthStage
    seven_start_actual = u32(data, seven_addr)
    # Find LFSR block in sevenStage
    custom_dec_off = find_lfsr_block(data, seven_start_actual, seven_dsz)
    if custom_dec_off is None:
        print('ERROR: could not locate customDecryptor in sevenStage')
        return
    custom_dec_addr = seven_start_actual + custom_dec_off
    decrypt_data6(data, custom_dec_addr)
    custom_dec = generate_custom_decryptor(data, custom_dec_addr)
    if custom_dec is None:
        return

    # PE32: eighthStageKey — scan backward from seven end
    eighth_key_off = seven_dsz - 0xD0
    eighth_key = u32(data, seven_start_actual + eighth_key_off)
    eighth_key = advance_key(eighth_key, 3)

    seven_cs = checksum_with_size_xor(data, seven_stage_cs_addr)
    eighth_addr = dp_base + 0xC0
    eighth_dsz = u32(data, eighth_addr + 12)
    fk8 = (header_checksum ^ fifth_cs ^ seven_cs ^ eighth_key) & 0xFFFFFFFF
    decrypt_and_decompress(data, eighth_addr, fk8, key_offsets, custom_dec)

    eighth_start = u32(data, eighth_addr)

    # ---- Final processing (PE32) ----
    off_import_table = 0x3C50 + ss_shift
    off_file_cs      = 0x3C68 + ss_shift
    off_compressed_info = 0x3C78 + ss_shift
    off_zero_list    = 0x3C80 + ss_shift
    off_file_lfsr    = 0x40EC + ss_shift

    # File checksums
    file_cs_addr_ptr = eighth_start + off_file_cs
    file_cs_addr = u32(data, file_cs_addr_ptr)
    file_cs_size = u32(data, file_cs_addr_ptr + 4)
    if file_cs_size > 0:
        file_cs_end = file_cs_addr + file_cs_size
        while file_cs_addr < file_cs_end:
            decrypt_data5(data, file_cs_addr, 16)
            file_cs_addr += 16
    else:
        while u32(data, file_cs_addr + 4) != 0:
            decrypt_data5(data, file_cs_addr, 16)
            file_cs_addr += 16

    # File decryptor
    lfsr_off = off_file_lfsr
    if not find_lfsr_block(data, eighth_start, eighth_dsz, lfsr_off):
        lfsr_off_found = find_lfsr_block(data, eighth_start, eighth_dsz, off_zero_list)
        if lfsr_off_found is not None:
            lfsr_off = lfsr_off_found
    file_dec_addr = eighth_start + lfsr_off
    decrypt_data6(data, file_dec_addr)
    file_dec = generate_custom_decryptor(data, file_dec_addr)
    if file_dec is None:
        return

    # Save EP from info[3] before overwrite
    original_ep = u32(data, info[3] + 0x10)

    # Save PE header values before file_data copy
    saved_pe80 = u32(data, pe_header + 0x80)
    saved_pe88 = u32(data, pe_header + 0x88)
    saved_pe8c = u32(data, pe_header + 0x8C)

    # Zero-out list (PE32: runs BEFORE decompression)
    zero_list_addr = eighth_start + off_zero_list
    zero_ptr = u32(data, zero_list_addr)
    while True:
        decrypt_data5(data, zero_ptr, 16)
        src3  = u32(data, zero_ptr)
        s_sz3 = u32(data, zero_ptr + 4)
        zero_ptr += 16
        if s_sz3 == 0: break
        if src3 + s_sz3 > len(data): break
        data[src3:src3 + s_sz3] = b'\x00' * s_sz3

    # File data decompression
    clean_file_data = bytearray(open(in_file, 'rb').read())
    compress_data_offset = ((~u32(file_data, 0x1080)) & 0xFFFFFFFF) + 0x1000
    compressed_info_addr = eighth_start + off_compressed_info
    compressed_info = u32(data, compressed_info_addr)
    while True:
        decrypt_data5(data, compressed_info, 16)
        src2  = u32(data, compressed_info)
        s_sz2 = u32(data, compressed_info + 4)
        dst2  = u32(data, compressed_info + 8)
        d_sz2 = u32(data, compressed_info + 12)
        compressed_info += 16
        if s_sz2 == 0: break
        file_src = src2 + compress_data_offset
        data[dst2:dst2 + s_sz2] = clean_file_data[file_src:file_src + s_sz2]
        aes_decrypt(data, dst2, s_sz2, key_offsets[2])
        _lut, _tt = file_dec
        data[dst2:dst2 + s_sz2] = bytearray(bytes(data[dst2:dst2 + s_sz2]).translate(_tt))
        if s_sz2 != d_sz2:
            decompress(data, dst2, dst2, key_offsets[0], s_sz2, d_sz2)

    # Section fixup
    data[:0x1000] = file_data[:0x1000]
    opt_hdr_size = u16(file_data, pe_header + 20)
    sec_hdr = pe_header + 24 + opt_hdr_size
    export_va   = u32(clean_file_data, pe_header + 24 + opt_hdr_size - 128)
    export_size = u32(clean_file_data, pe_header + 24 + opt_hdr_size - 124)
    export_file_off = 0
    text_off = 0; text_size = 0
    while u32(file_data, sec_hdr + 8) != 0:
        va   = u32(file_data, sec_hdr + 12)
        sz   = u32(file_data, sec_hdr + 8)
        f_off = u32(file_data, sec_hdr + 20)
        sec_name = file_data[sec_hdr:sec_hdr + 8]
        if sec_name[:5] == b'.text':
            text_size = sz; text_off = va
        if export_va >= va and export_va + export_size <= va + sz:
            export_file_off = export_va - va + f_off
        w32(data, sec_hdr + 16, sz)
        w32(data, sec_hdr + 20, va)
        sec_hdr += 40
    if export_size != 0 and export_file_off != 0:
        data[export_va:export_va + export_size] = file_data[export_file_off:export_file_off + export_size]

    # .text decrypt with decrypt_data8
    if text_size > 0 and text_off > 0:
        num_pages = text_size // 0x1000
        for page in range(num_pages):
            page_key = 0x8000 * (page + 1)
            page_addr = text_off + page * 0x1000
            count = 0x1000 >> 4
            key_state = page_key
            rk = ((key_state >> 15) | (key_state << 17)) & 0xFFFFFFFF
            key_state = rk
            for i in range(1, count):
                rk = ((key_state >> 15) | (key_state << 17)) & 0xFFFFFFFF
                ri = (rk + i) & 0xFFFFFFFF
                key_state = (ri + i) & 0xFFFFFFFF
                tidx = page_addr + i * 16 + (ri & 0xF)
                data[tidx] = (data[tidx] ^ key_state) & 0xFF

    # Fix data directories (PE32)
    exe_pe = u32(data, 60)
    w32(data, exe_pe + 0x80, saved_pe80)
    w32(data, exe_pe + 0x88, saved_pe88)
    w32(data, exe_pe + 0x8C, saved_pe8c)
    w32(data, exe_pe + 0xA0, 0)
    w32(data, exe_pe + 0xA4, 0)
    w32(data, exe_pe + 0xB0, 0)
    w32(data, exe_pe + 0xB4, 0)
    # PE32: clear DllCharacteristics
    w16(data, exe_pe + 0x5E, 0)

    # Import table (PE32, 4-byte thunks)
    import_table_addr = eighth_start + off_import_table
    import_table_ptr = u32(data, import_table_addr)
    idt_size = u32(data, import_table_addr + 4)
    idt_pos = import_table_ptr
    idt_end = import_table_ptr + idt_size
    while idt_pos + 20 <= idt_end:
        ilt_rva  = u32(data, idt_pos)
        name_rva = u32(data, idt_pos + 12)
        iat_rva  = u32(data, idt_pos + 16)
        if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
            break
        if 0 < name_rva < len(data):
            decrypt_data7(data, name_rva, name_rva & 0xFF)
        thunk_pos = ilt_rva if (0 < ilt_rva < len(data)) else iat_rva
        if 0 < thunk_pos < len(data):
            while True:
                thunk_val = u32(data, thunk_pos)
                if thunk_val == 0: break
                if not (thunk_val & 0x80000000):
                    if thunk_val + 2 < len(data):
                        decrypt_data7(data, thunk_val + 2, thunk_val & 0xFF)
                        w16(data, thunk_val, 0)
                thunk_pos += 4
        idt_pos += 20

    # Update PE header
    w32(data, exe_pe + 0x80, import_table_ptr)
    w32(data, exe_pe + 0x84, idt_size)

    # Fix IAT directory
    iat_min = 0xFFFFFFFF; iat_max = 0
    idt_scan = import_table_ptr
    while idt_scan + 20 <= import_table_ptr + idt_size:
        s_ilt = u32(data, idt_scan); s_name = u32(data, idt_scan + 12); s_iat = u32(data, idt_scan + 16)
        if s_ilt == 0 and s_name == 0 and s_iat == 0: break
        if s_iat < iat_min: iat_min = s_iat
        tp = s_iat
        while u32(data, tp) != 0: tp += 4
        tp += 4
        if tp > iat_max: iat_max = tp
        idt_scan += 20
    if iat_min < iat_max:
        w32(data, exe_pe + 0xC0, iat_min)
        w32(data, exe_pe + 0xC4, iat_max - iat_min)

    # EP (PE32)
    real_ep = u32(file_data, pe_header + 40)
    w32(data, exe_pe + 40, real_ep)

    # Write output
    dot = in_file.rfind('.')
    if dot >= 0:
        out_file = in_file[:dot] + '.unpack' + in_file[dot:]
    else:
        out_file = in_file + '.unpack'
    print(f'\n=== Writing {out_file} ===')
    with open(out_file, 'wb') as f:
        f.write(data)
    print(f'Done! {_elapsed()}')


if __name__ == '__main__':
    main()
