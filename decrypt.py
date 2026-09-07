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

def u16(data, off):
    return _u16.unpack_from(data, off)[0]

def u32(data, off):
    return _u32.unpack_from(data, off)[0]

def u64(data, off):
    return _u64.unpack_from(data, off)[0]

def w16(data, off, val):
    _u16.pack_into(data, off, val & 0xFFFF)

def w32(data, off, val):
    _u32.pack_into(data, off, val & 0xFFFFFFFF)

def bswap32(v):
    return int.from_bytes((v & 0xFFFFFFFF).to_bytes(4, 'little'), 'big')

# Pre-built ror8/rol8 lookup tables: _ROR8[shift][byte], _ROL8[shift][byte]
_ROR8 = [[0]*256 for _ in range(8)]
_ROL8 = [[0]*256 for _ in range(8)]
for _s in range(8):
    for _b in range(256):
        _ROR8[_s][_b] = ((_b >> _s) | (_b << (8 - _s))) & 0xFF
        _ROL8[_s][_b] = ((_b << _s) | (_b >> (8 - _s))) & 0xFF

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

def align_up(value, alignment):
    return (value + alignment - 1) // alignment * alignment

def compact_memory_image_to_pe(data, pe_header, *, file_alignment=0x200, header_size=0x400):
    """Convert the unpacked RVA-addressed image back to a compact PE file layout.

    CrackProof reconstruction works on a memory-image-like buffer where section
    data is addressed by RVA. Writing that buffer directly makes PointerToRawData
    mirror VirtualAddress and bloats the output. The known-good EXE samples use a
    normal disk layout: headers at 0x400, sections packed consecutively, and raw
    sizes trimmed to the last meaningful byte with FileAlignment padding.
    """
    opt_hdr_size = u16(data, pe_header + 20)
    opt_hdr = pe_header + 24
    sec_table = opt_hdr + opt_hdr_size
    num_sections = u16(data, pe_header + 6)

    old_file_alignment = u32(data, opt_hdr + 36)
    old_header_size = u32(data, opt_hdr + 60)

    sections = []
    for idx in range(num_sections):
        sec_off = sec_table + idx * 40
        name = bytes(data[sec_off:sec_off + 8]).rstrip(b'\x00').decode('ascii', errors='replace')
        virtual_size = u32(data, sec_off + 8)
        virtual_address = u32(data, sec_off + 12)
        characteristics = u32(data, sec_off + 36)
        sections.append({
            'idx': idx,
            'off': sec_off,
            'name': name,
            'virtual_size': virtual_size,
            'virtual_address': virtual_address,
            'characteristics': characteristics,
        })

    raw_cursor = header_size
    raw_layout = []
    for sec in sections:
        va = sec['virtual_address']
        vsize = sec['virtual_size']
        section_data = data[va:va + vsize] if va + vsize <= len(data) else data[va:]

        last_nonzero = -1
        for pos in range(len(section_data) - 1, -1, -1):
            if section_data[pos] != 0:
                last_nonzero = pos
                break

        meaningful_size = last_nonzero + 1 if last_nonzero >= 0 else 0
        raw_size = align_up(meaningful_size, file_alignment) if meaningful_size else 0
        if vsize and raw_size == 0:
            raw_size = file_alignment
        raw_size = min(raw_size, align_up(len(section_data), file_alignment))

        raw_ptr = raw_cursor if raw_size else 0
        raw_layout.append((sec, section_data, raw_ptr, raw_size, meaningful_size))
        if raw_size:
            raw_cursor = align_up(raw_cursor + raw_size, file_alignment)

    compact = bytearray(raw_cursor)
    compact[:min(header_size, len(data))] = data[:min(header_size, len(data))]

    # FileAlignment and SizeOfHeaders must describe the compact disk layout.
    w32(compact, opt_hdr + 36, file_alignment)
    w32(compact, opt_hdr + 60, header_size)

    print('\n=== Compacting PE raw layout ===')
    print(f'  FileAlignment: 0x{old_file_alignment:X} -> 0x{file_alignment:X}')
    print(f'  SizeOfHeaders: 0x{old_header_size:X} -> 0x{header_size:X}')

    for sec, section_data, raw_ptr, raw_size, meaningful_size in raw_layout:
        sec_off = sec['off']
        w32(compact, sec_off + 16, raw_size)
        w32(compact, sec_off + 20, raw_ptr)
        if raw_size:
            copy_size = min(raw_size, len(section_data))
            compact[raw_ptr:raw_ptr + copy_size] = section_data[:copy_size]
        print(
            f'  [{sec["idx"]}] {sec["name"]:8s}: '
            f'RVA=0x{sec["virtual_address"]:08X} VS=0x{sec["virtual_size"]:08X} '
            f'raw=0x{raw_ptr:08X}/0x{raw_size:08X} meaningful=0x{meaningful_size:08X}'
        )

    print(f'  Output image: 0x{len(data):X} -> compact file 0x{len(compact):X}')
    return compact

def move_pe32_imports_to_kmiat(data, pe_header, *, section_size=0x7000):
    """Move rebuilt PE32 import metadata into the last section as .kmiat.

    The reference unpacked EXEs keep the loader-written IAT in the old .idata
    range, but place the import descriptors, lookup tables, and names in a final
    executable/readable/writable .kmiat section. This mirrors that layout without
    depending on bytes from a known-good sample.
    """
    opt_hdr_size = u16(data, pe_header + 20)
    opt_hdr = pe_header + 24
    sec_table = opt_hdr + opt_hdr_size
    num_sections = u16(data, pe_header + 6)
    if num_sections == 0:
        return data

    import_rva = u32(data, pe_header + 0x80)
    import_size = u32(data, pe_header + 0x84)
    if not (0x1000 < import_rva < len(data) and 0 < import_size < section_size):
        return data

    descriptors = []
    idt_pos = import_rva
    while idt_pos + 20 <= len(data):
        oft_rva = u32(data, idt_pos)
        time_date = u32(data, idt_pos + 4)
        fwd_chain = u32(data, idt_pos + 8)
        name_rva = u32(data, idt_pos + 12)
        iat_rva = u32(data, idt_pos + 16)
        if oft_rva == 0 and name_rva == 0 and iat_rva == 0:
            break
        if not (0x1000 < name_rva < len(data)):
            break

        dll_name = get_string(data, name_rva)
        thunk_rva = oft_rva if 0x1000 < oft_rva < len(data) else iat_rva
        functions = []
        thunk_pos = thunk_rva
        while 0x1000 < thunk_pos + 4 <= len(data):
            thunk_val = u32(data, thunk_pos)
            if thunk_val == 0:
                break
            if thunk_val & 0x80000000:
                functions.append(('ordinal', thunk_val & 0xFFFF))
            else:
                hint = u16(data, thunk_val) if thunk_val + 2 <= len(data) else 0
                func_name = get_string(data, thunk_val + 2) if thunk_val + 2 < len(data) else ''
                functions.append(('name', hint, func_name))
            thunk_pos += 4

        descriptors.append({
            'time_date': time_date,
            'fwd_chain': fwd_chain,
            'dll_name': dll_name,
            'sort_name': dll_name.lower(),
            'iat_rva': iat_rva,
            'functions': functions,
        })
        idt_pos += 20

    if not descriptors:
        return data

    for desc in descriptors:
        lower_name = desc['dll_name'].lower()
        if lower_name.startswith('api-ms-win-crt-'):
            desc['dll_name'] = 'ucrtbase.dll'
        else:
            desc['dll_name'] = lower_name
    descriptors.sort(key=lambda desc: desc['iat_rva'])

    last_sec = sec_table + (num_sections - 1) * 40
    kmiat_rva = u32(data, last_sec + 12)
    if kmiat_rva <= 0 or kmiat_rva + section_size > len(data):
        if kmiat_rva + section_size > len(data):
            data.extend(bytearray(kmiat_rva + section_size - len(data)))

    data[kmiat_rva:kmiat_rva + section_size] = bytearray(section_size)

    idt_size = (len(descriptors) + 1) * 20
    oft_start = kmiat_rva
    idt_rva = oft_start
    for desc in descriptors:
        idt_rva += (len(desc['functions']) + 1) * 4
    idt_rva = align_up(idt_rva + 0x2C, 4)

    name_pos = idt_rva + idt_size
    for desc in descriptors:
        name_pos += len(desc['dll_name'].encode('ascii', errors='replace')) + 1
        for func in desc['functions']:
            if func[0] == 'name':
                name_pos += 2 + len(func[2].encode('ascii', errors='replace')) + 1

    if name_pos > kmiat_rva + section_size:
        print('  WARNING: .kmiat section too small for relocated imports; keeping existing import table')
        return data

    oft_pos = oft_start
    name_pos = idt_rva + idt_size

    for idx, desc in enumerate(descriptors):
        idt_entry = idt_rva + idx * 20
        current_oft = oft_pos
        w32(data, idt_entry, current_oft)
        w32(data, idt_entry + 4, desc['time_date'])
        w32(data, idt_entry + 8, desc['fwd_chain'])
        dll_name_pos = name_pos
        w32(data, idt_entry + 12, dll_name_pos)
        w32(data, idt_entry + 16, desc['iat_rva'])

        dll_name_bytes = desc['dll_name'].encode('ascii', errors='replace') + b'\x00'
        data[dll_name_pos:dll_name_pos + len(dll_name_bytes)] = dll_name_bytes
        name_pos += len(dll_name_bytes)

        for func in desc['functions']:
            if func[0] == 'ordinal':
                w32(data, oft_pos, 0x80000000 | func[1])
            else:
                hint_name_rva = name_pos
                w32(data, oft_pos, hint_name_rva)
                w16(data, hint_name_rva, func[1])
                func_name_bytes = func[2].encode('ascii', errors='replace') + b'\x00'
                data[hint_name_rva + 2:hint_name_rva + 2 + len(func_name_bytes)] = func_name_bytes
                name_pos += 2 + len(func_name_bytes)
            oft_pos += 4
        w32(data, oft_pos, 0)
        oft_pos += 4

    data[idt_rva + len(descriptors) * 20:idt_rva + idt_size] = bytearray(20)

    data[last_sec:last_sec + 8] = b'.kmiat\x00\x00'
    w32(data, last_sec + 8, section_size)
    w32(data, last_sec + 16, section_size)
    w32(data, last_sec + 36, 0xE0000060)
    w32(data, pe_header + 0x80, idt_rva)
    w32(data, pe_header + 0x84, idt_size)
    w32(data, pe_header + 80, kmiat_rva + section_size)

    print('\n=== Moving imports to .kmiat ===')
    print(f'  DLLs: {len(descriptors)}, .kmiat RVA=0x{kmiat_rva:08X}, Import RVA=0x{idt_rva:08X}, Size=0x{idt_size:08X}')
    return data

def pe32_imports_already_match_idata_layout(data, pe_header):
    """Return True when PE32 imports are already in the original .idata layout."""
    opt_hdr_size = u16(data, pe_header + 20)
    sec_table = pe_header + 24 + opt_hdr_size
    num_sections = u16(data, pe_header + 6)
    import_rva = u32(data, pe_header + 0x80)
    import_size = u32(data, pe_header + 0x84)

    if not (import_rva > 0 and import_size > 0):
        return False

    for idx in range(num_sections):
        sec_off = sec_table + idx * 40
        sec_name = data[sec_off:sec_off + 8]
        if sec_name[:6] != b'.idata':
            continue
        sec_va = u32(data, sec_off + 12)
        sec_size = max(u32(data, sec_off + 8), u32(data, sec_off + 16))
        sec_end = sec_va + sec_size
        if not (sec_va <= import_rva < sec_end and import_rva + import_size <= sec_end):
            continue

        first_oft = u32(data, import_rva)
        first_name = u32(data, import_rva + 12)
        first_iat = u32(data, import_rva + 16)
        if not (sec_va <= first_oft < sec_end and sec_va <= first_iat < sec_end):
            return False
        if not (0x1000 < first_name < len(data)):
            return False

        dll_name = data[first_name:first_name + 80].split(b'\x00')[0]
        if not dll_name.lower().endswith(b'.dll'):
            return False

        iat_min = first_iat
        iat_max = first_iat
        idt_pos = import_rva
        while idt_pos + 20 <= len(data):
            oft_rva = u32(data, idt_pos)
            name_rva = u32(data, idt_pos + 12)
            iat_rva = u32(data, idt_pos + 16)
            if oft_rva == 0 and name_rva == 0 and iat_rva == 0:
                break
            if not (sec_va <= oft_rva < sec_end and sec_va <= iat_rva < sec_end):
                return False
            thunk = iat_rva
            while thunk + 4 <= sec_end:
                thunk_val = u32(data, thunk)
                thunk += 4
                if thunk_val == 0:
                    break
            iat_min = min(iat_min, iat_rva)
            iat_max = max(iat_max, thunk)
            idt_pos += 20

        if iat_max > iat_min:
            w32(data, pe_header + 0xD8, iat_min)
            w32(data, pe_header + 0xDC, iat_max - iat_min)
        print('  PE32 imports already use .idata layout; skipping .kmiat relocation')
        return True
    return False

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

# ---------- AES (optimized: array.array for direct indexing) ----------
_cm1 = _cm2 = _cm3 = _cm4 = _sbox = None  # array.array('I')

_AES_TABLE_FILES = ('aes_colum_mix1', 'aes_colum_mix2', 'aes_colum_mix3',
                    'aes_colum_mix4', 'aes_sbox')


def gen_aes_tables():
    """Generate the AES decryption tables (Td0-3 + inverse S-box, each replicated
    0x01010101) entirely in code, byte-identical to the aes_* data files. This
    lets the tool run with no external table files (the tables are standard AES
    constants, not sample-specific data)."""
    global _cm1, _cm2, _cm3, _cm4, _sbox
    def _xt(a):
        a <<= 1
        return (a ^ 0x11B) & 0xFF if a & 0x100 else a & 0xFF
    exp = [0] * 256; log = [0] * 256; x = 1
    for i in range(255):
        exp[i] = x; log[x] = i; x ^= _xt(x)        # x *= 3 (generator)
    def _inv(a):
        return 0 if a == 0 else exp[(255 - log[a]) % 255]
    sbox = []
    for i in range(256):
        b = _inv(i); s = b
        for _ in range(4):
            b = ((b << 1) | (b >> 7)) & 0xFF; s ^= b
        sbox.append((s ^ 0x63) & 0xFF)
    isb = [0] * 256
    for i in range(256):
        isb[sbox[i]] = i
    def _mul(a, b):
        r = 0
        for _ in range(8):
            if b & 1: r ^= a
            a = _xt(a); b >>= 1
        return r & 0xFF
    def _ror(w, n):
        return ((w >> n) | (w << (32 - n))) & 0xFFFFFFFF
    td0 = [((_mul(isb[a], 0x0E) << 24) | (_mul(isb[a], 0x09) << 16)
            | (_mul(isb[a], 0x0D) << 8) | _mul(isb[a], 0x0B)) & 0xFFFFFFFF
           for a in range(256)]
    _cm1 = array.array('I', td0)
    _cm2 = array.array('I', [_ror(w, 8) for w in td0])
    _cm3 = array.array('I', [_ror(w, 16) for w in td0])
    _cm4 = array.array('I', [_ror(w, 24) for w in td0])
    _sbox = array.array('I', [(0x01010101 * isb[i]) & 0xFFFFFFFF for i in range(256)])


def load_aes_tables(base_dir):
    """Load the AES tables from `base_dir`; if the directory or files are not
    available, generate them in code (they are standard AES constants)."""
    global _cm1, _cm2, _cm3, _cm4, _sbox
    if base_dir and all(os.path.exists(os.path.join(base_dir, n)) for n in _AES_TABLE_FILES):
        def _load(name):
            raw = open(os.path.join(base_dir, name), 'rb').read()
            return array.array('I', raw)  # native u32 array, direct index
        _cm1 = _load('aes_colum_mix1')
        _cm2 = _load('aes_colum_mix2')
        _cm3 = _load('aes_colum_mix3')
        _cm4 = _load('aes_colum_mix4')
        _sbox = _load('aes_sbox')
    else:
        gen_aes_tables()

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

# Cross-layout target-header trailer (written by encrypt_crackproof.py for packs
# whose target program layout differs from the donor stub). It carries the
# target's real section table + image sizing so we can emit a valid final PE
# instead of the donor's layout. Absent on identity packs and stock CrackProof
# samples -> parsing returns None and unpacking is unchanged.
_TGT_HDR_MAGIC = b'CPXSECT\x00'


def _parse_target_hdr_trailer(buf):
    """Return dict(nsec, simg, shdr, flags, sectbl, hdr) if buf ends with a valid
    trailer, else None. Layout: payload + crc32(payload)[4] + len(payload)[4] +
    MAGIC[8]. payload = <IIII nsec,simg,shdr,flags> + sectbl + optional
    <I hdrlen> + hdrbytes (verbatim target header [0:SizeOfHeaders])."""
    if len(buf) < 32 or bytes(buf[-8:]) != _TGT_HDR_MAGIC:
        return None
    plen = struct.unpack_from('<I', buf, len(buf) - 12)[0]
    crc = struct.unpack_from('<I', buf, len(buf) - 16)[0]
    start = len(buf) - 16 - plen
    if start < 0 or plen < 16:
        return None
    payload = bytes(buf[start:len(buf) - 16])
    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
        return None
    nsec, simg, shdr, flags = struct.unpack_from('<IIII', payload, 0)
    sectbl = payload[16:16 + nsec * 40]
    if len(sectbl) != nsec * 40:
        return None
    # Optional verbatim target header tail (new format). Absent in old packs.
    hdr = None
    tail = 16 + nsec * 40
    if len(payload) >= tail + 4:
        hdr_len = struct.unpack_from('<I', payload, tail)[0]
        if 0 < hdr_len <= len(payload) - (tail + 4):
            hdr = payload[tail + 4:tail + 4 + hdr_len]
    return dict(nsec=nsec, simg=simg, shdr=shdr, flags=flags, sectbl=sectbl, hdr=hdr)


def _apply_target_hdr(data, tgt_hdr):
    """Rewrite NumberOfSections / SizeOfImage / SizeOfHeaders / section table with
    the carried target values and resize the flat (file==RVA) image to the target
    SizeOfImage. decrypt's own EP / import / resource restore is left intact."""
    simg = tgt_hdr['simg']
    hdr = tgt_hdr.get('hdr')
    if hdr is not None:
        # New format: restore the target's verbatim header region (DOS header +
        # DOS stub + PE header at the *target's own* e_lfanew + optional header +
        # data directories + section table), overwriting the shell stub's header
        # so e_lfanew / DOS stub / header fields match the target byte-for-byte.
        # This is what makes cross-stub-layout repacks (e.g. Sinmai e_lfanew=0x110
        # packed with an amdaemon-stub e_lfanew=0x128) reproduce the original
        # header exactly. The decoded program body [SizeOfHeaders:] already
        # matches the target, so header + body == the original target.
        data[0:len(hdr)] = hdr
        pe = struct.unpack_from('<I', data, 0x3C)[0]
        optsz = struct.unpack_from('<H', data, pe + 0x14)[0]
        nsec = struct.unpack_from('<H', data, pe + 6)[0]
        st = pe + 0x18 + optsz
        # The reconstructed image is a flat file==RVA dump. The target's header is
        # itself already flat (PtrRaw==VA), so this fixup is normally a no-op, but
        # re-assert it defensively for any compact-PtrRaw target header.
        for i in range(nsec):
            s = st + i * 40
            va = struct.unpack_from('<I', data, s + 12)[0]
            vs = struct.unpack_from('<I', data, s + 8)[0]
            rsz = vs
            if va + rsz > simg:
                rsz = simg - va if simg > va else 0
            w32(data, s + 16, rsz)   # SizeOfRawData = VirtualSize
            w32(data, s + 20, va)    # PointerToRawData = VirtualAddress
        if len(data) < simg:
            data.extend(b'\x00' * (simg - len(data)))
        elif len(data) > simg:
            del data[simg:]
        return
    # Legacy format (no verbatim header): patch the shell header in place.
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = tgt_hdr['nsec']; shdr = tgt_hdr['shdr']
    optsz = struct.unpack_from('<H', data, pe + 0x14)[0]
    donor_nsec = struct.unpack_from('<H', data, pe + 6)[0]
    w16(data, pe + 6, nsec)
    w32(data, pe + 0x50, simg)
    w32(data, pe + 0x54, shdr)
    st = pe + 0x18 + optsz
    data[st:st + nsec * 40] = tgt_hdr['sectbl']
    # The reconstructed image is a flat file==RVA dump, so each section's raw data
    # lives at its VirtualAddress, NOT at the target's (compact) PointerToRawData.
    # Rewrite PointerToRawData = VirtualAddress and SizeOfRawData = VirtualSize so the
    # Windows loader maps the correct bytes. (For targets that were already flat
    # file==RVA, PtrRaw already equals VA, so this is a no-op.)
    for i in range(nsec):
        s = st + i * 40
        va = struct.unpack_from('<I', data, s + 12)[0]
        vs = struct.unpack_from('<I', data, s + 8)[0]
        rsz = vs
        if va + rsz > simg:
            rsz = simg - va if simg > va else 0
        w32(data, s + 16, rsz)   # SizeOfRawData = VirtualSize
        w32(data, s + 20, va)    # PointerToRawData = VirtualAddress
    if nsec < donor_nsec:
        z = st + nsec * 40
        data[z:z + (donor_nsec - nsec) * 40] = b'\x00' * ((donor_nsec - nsec) * 40)
    if len(data) < simg:
        data.extend(b'\x00' * (simg - len(data)))
    elif len(data) > simg:
        del data[simg:]


def main():
    if len(sys.argv) < 2:
        print('Usage: python decrypt_crackproof.py <input_file> [aes_tables_dir]')
        return

    in_file = sys.argv[1]
    # AES tables are standard constants, so generate them once at startup by
    # default. Passing a directory keeps compatibility with the legacy files.
    aes_dir = sys.argv[2] if len(sys.argv) >= 3 else None

    if aes_dir and all(os.path.exists(os.path.join(aes_dir, n)) for n in _AES_TABLE_FILES):
        print(f'Loading AES tables from {aes_dir}')
    else:
        print('Generating AES tables in code (no external table files)')
    load_aes_tables(aes_dir)

    print(f'Reading {in_file}')
    file_data = bytearray(open(in_file, 'rb').read())
    _tgt_hdr = _parse_target_hdr_trailer(file_data)
    if _tgt_hdr is not None:
        print(f'  [+] cross-layout target-header trailer found: nsec={_tgt_hdr["nsec"]} '
              f'SizeOfImage=0x{_tgt_hdr["simg"]:X} (will rebuild final section table)')

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

        # Save these values for later (in case metadata overwrites them with 0)
        saved_import_rva = import_rva
        saved_import_size = import_size

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

        # Build candidate list: scan the fifthStage for non-zero 4-byte values.
        # We do NOT filter "ASCII-looking" values - sgimagemount.exe's sevenKey
        # is 0x4F466231 ('1bFO') which a strict ASCII filter would skip.
        seven_key_candidates = []
        for sk_off in [0x7B0, 0x7A8, 0x7A0, 0x798, 0x880, 0x878, 0x870, 0x868, 0x860, 0x858, 0x830]:
            if sk_off + 4 <= fifth_dsz:
                seven_key_candidates.append(sk_off)
        # Then scan the entire second half of fifthStage for non-zero values
        # (trial-decrypt is the real validator).
        for sk_off in range(max(0, fifth_dsz // 2), fifth_dsz - 4, 4):
            if sk_off in seven_key_candidates:
                continue
            val = u32(data, fifth_start_actual + sk_off)
            if val != 0 and val != 0xCCCCCCCC:
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

        # Find the correct file LFSR: scan backward, validate LFSR-0x58 has a valid pointer.
        # Across known-good samples (amdaemon, sgxsegaboot, sgosupdate, util_sgxsegaboot)
        # fileCS always lives just past the metadata region at info[3] (offset
        # info[3]+0x100..info[3]+0x10000). False-positive LFSR blocks earlier in the
        # eighthStage often have pointer fields that look valid in a generic range
        # check but point far away from info[3] - prefer the candidate whose fileCS
        # is closest to (but greater than) info[3].
        off_file_lfsr = None
        info3 = info[3]
        best_dist = None
        for lfsr_off in all_lfsrs:
            cs_off = lfsr_off - 0x58
            if cs_off < 0:
                continue
            cs_val = u32(data, eighth_start + cs_off)
            if not (0x1000 < cs_val < len(data)):
                continue
            # Distance metric: how far past info[3] does fileCS sit?
            if cs_val < info3:
                continue
            dist = cs_val - info3
            if best_dist is None or dist < best_dist:
                best_dist = dist
                off_file_lfsr = lfsr_off

        if off_file_lfsr is None:
            # Fallback to legacy behaviour: pick the *last* LFSR with any in-image
            # pointer (preserves compatibility with samples we already handle).
            for lfsr_off in reversed(all_lfsrs):
                cs_off = lfsr_off - 0x58
                if cs_off >= 0:
                    cs_val = u32(data, eighth_start + cs_off)
                    if 0x1000 < cs_val < len(data):
                        off_file_lfsr = lfsr_off
                        break

        if off_file_lfsr is not None:
            cs_off = off_file_lfsr - 0x58
            cs_val = u32(data, eighth_start + cs_off)
            print(f'  fileLFSR at eighth+0x{off_file_lfsr:X} (fileCS at +0x{cs_off:X} -> 0x{cs_val:08X})')
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
        # NOTE: anchor_off can be 0 (no anchor found AND fallback hit 0) but more
        # importantly `if anchor_off` would treat anchor at +0 as missing. Use
        # explicit None check.
        scan_from = anchor_off if anchor_off is not None else max(off_file_lfsr - 0x400, 0)
        all_ptrs = []
        for doff in range(scan_from, off_file_lfsr, 4):
            val = u32(data, eighth_start + doff)
            # Small images (e.g. 0x40000 byte EXEs / DLLs) have RVAs well below
            # 0x10000.  Use a minimum that's still high enough to skip section
            # header noise (>= 0x1000) but doesn't drop legitimate small-image
            # pointers.
            if 0x1000 < val < len(data) - 16:
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
            # Prefer the candidate whose pointer sits closest to (but >= ) info[3]:
            # the real compressedInfo table lives just past the metadata at info[3]
            # (info[3]+~0x280), while decoy pointers sit much higher in the shell.
            # Picking the lowest in-shell pointer avoids false positives that only
            # validate when the image is grown (relocated) and len(data) is larger.
            info3v = info[3]
            ranked = sorted(compress_candidates,
                            key=lambda c: (c[1] - info3v) if c[1] >= info3v else (1 << 62))
            off_compressed_info = ranked[0][0]
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

        # Save metadata before decompression for corruption detection. Save enough
        # to cover both Layout-A (info3+0x40,+144) and Layout-B (info3+0x10,+0x290)
        # metadata so OVERLAP packs (whose program tail decompresses over [info3:])
        # can still recover the shell's EP/data-dirs from this pre-decompression copy.
        meta_before = bytes(data[info[3]:info[3] + 0x300])

        compressed_info_addr = eighth_start + off_compressed_info
        compressed_info = u32(data, compressed_info_addr)
        print(f'  compressDataOffset = 0x{compress_data_offset:X}')
        print(f'  compressedDataInfo = 0x{compressed_info:08X}')

        # OVERLAP packs decompress the program tail over [info3:image], which clobbers
        # BOTH the file-decryptor tables (AES schedule key_offsets[2], LZ huffman
        # key_offsets[0]) AND the compressedInfo/zero-list table itself (at info3+0x280).
        # The runtime reads the whole table and loads the key tables once; mirror that:
        #   (1) read ALL records (compressedInfo + zero-list) BEFORE decompressing,
        #   (2) grow the buffer to cover every record destination + target image (a
        #       large OVERLAP target's image exceeds the packed-file-derived buffer),
        #   (3) cache the key tables in a scratch region placed ABOVE the image so
        #       the decompression writes can never clobber it.

        # Phase 1: read all records while the table is still intact.
        recs = []
        while True:
            decrypt_data5(data, compressed_info, 16)
            s2 = u32(data, compressed_info); ssz2 = u32(data, compressed_info + 4)
            d2 = u32(data, compressed_info + 8); dsz2 = u32(data, compressed_info + 12)
            compressed_info += 16
            if ssz2 == 0:
                break
            recs.append((s2, ssz2, d2, dsz2))
        zero_recs = []
        while True:
            decrypt_data5(data, compressed_info, 16)
            s3 = u32(data, compressed_info); ssz3 = u32(data, compressed_info + 4)
            compressed_info += 16
            if ssz3 == 0:
                break
            zero_recs.append((s3, ssz3))

        # Grow the buffer so every record destination (and the carried target
        # SizeOfImage) is in-bounds. Large OVERLAP repacks whose image exceeds the
        # packed-file-derived buffer would otherwise overflow at dst2 inside
        # aes_decrypt (struct.error: buffer too small) and clobber the scratch key
        # cache, which must live ABOVE the reconstructed image.
        need = len(data)
        for _s2, _ssz2, _d2, _dsz2 in recs:
            need = max(need, _d2 + _ssz2, _d2 + _dsz2)
        if _tgt_hdr is not None:
            need = max(need, _tgt_hdr['simg'])
        if len(data) < need:
            data.extend(b'\x00' * (need - len(data)))

        # Scratch ABOVE the image: cache the key tables the decompression clobbers.
        _scratch = len(data)
        data.extend(b'\x00' * 0x4000)
        ko2_s = _scratch
        data[ko2_s:ko2_s + 0x1000] = data[key_offsets[2]:key_offsets[2] + 0x1000]
        ko0_s = _scratch + 0x2000
        data[ko0_s:ko0_s + 0x1000] = data[key_offsets[0]:key_offsets[0] + 0x1000]

        # The OVERLAP tail [info3:image] of the target is zero-initialised BSS:
        # the packer stores only non-zero pages, so no compressedInfo record
        # covers it. The packed file, however, still holds the shell's
        # table/metadata/payload bytes throughout that range. Clear [info3:image]
        # (the key tables that live at ~info3+0x280 are already cached above) so
        # the uncovered tail reconstructs as the target's zeros instead of leaked
        # shell bytes. Records that DO land here (rare non-zero tail data) are
        # re-applied by Phase 2 below. Only targets whose image exceeds info3 have
        # this tail; image<=info3 packs leave _scratch==info3-ish so this is a
        # no-op and the 84 small/medium samples are unaffected.
        if info[3] < _scratch:
            data[info[3]:_scratch] = b'\x00' * (_scratch - info[3])

        # Phase 2: decompress (may overwrite the table region; records already read).
        block_count = 0
        decomp_ranges = []
        for src2, s_sz2, dst2, d_sz2 in recs:
            decomp_ranges.append((dst2, d_sz2))
            file_src = src2 + compress_data_offset
            chunk = clean_file_data[file_src:file_src + s_sz2]
            if len(chunk) < s_sz2:               # source truncated -> zero-fill tail
                chunk = chunk + b'\x00' * (s_sz2 - len(chunk))
            data[dst2:dst2 + s_sz2] = chunk
            aes_decrypt(data, dst2, s_sz2, ko2_s)
            _lut, _tt = file_dec
            data[dst2:dst2 + s_sz2] = bytearray(bytes(data[dst2:dst2 + s_sz2]).translate(_tt))
            if s_sz2 != d_sz2:
                decompress(data, dst2, dst2, ko0_s, s_sz2, d_sz2)
            block_count += 1
        del data[_scratch:]   # drop scratch
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
        if meta_before[:0x100] != meta_after:
            changed = sum(1 for a,b in zip(meta_before[:0x100], meta_after) if a != b)
            print(f'  WARNING: metadata at info[3]=0x{info[3]:X} changed by decompression ({changed} bytes differ)')
        else:
            print(f'  Metadata at info[3]=0x{info[3]:X} NOT affected by decompression')

        # ---- Zero-out list (C# DLL: runs AFTER file decompression) ----
        zero_count = 0
        zero_ranges = []
        for src3, s_sz3 in zero_recs:
            zero_ranges.append((src3, s_sz3))
            data[src3:src3 + s_sz3] = b'\x00' * s_sz3
            zero_count += 1
        print(f'  Zeroed {zero_count} regions')
        for zr, zs in zero_ranges[:5]:
            print(f'    0x{zr:X} - 0x{zr+zs:X} (0x{zs:X})')
        if len(zero_ranges) > 5:
            print(f'    ... ({len(zero_ranges)-5} more)')

        # ---- Metadata + Import + EP + .text decryption (PE32+) ----
        # CrackProof stores the original entry point and data directories in
        # one of two encrypted metadata blocks.  Layout depends on shell vintage:
        #   Layout B (new shell): decrypt 0x290 bytes from info[3]+0x10. EP @+0x20, dirs @+0x30.
        #   Layout A (old shell): decrypt 144  bytes from info[3]+0x40. EP @+0x40, dirs @+0x50.
        # We dual-try both, pick the EP that lies inside the image, and pick
        # the Import RVA among metadata-A / metadata-B / anchor candidates by
        # validating that the candidate points at a plausible IDT entry.
        print('\n=== Metadata + Import reconstruction ===')

        # OVERLAP packs reconstruct the program tail over [info3:tgt], clobbering the
        # shell metadata at info3+0x10/0x40. Restore the pre-decompression metadata
        # (meta_before) just for the EP/data-dir read, then put the program tail back.
        live_meta = bytes(data[info[3]:info[3] + 0x300])
        data[info[3]:info[3] + 0x300] = meta_before

        backup = bytes(data[info[3] + 0x10:info[3] + 0x10 + 0x290])
        decrypt_data5(data, info[3] + 0x10, 0x290)
        ep_B   = u32(data, info[3] + 0x20)
        dirs_B = bytes(data[info[3] + 0x30:info[3] + 0x30 + 128])
        data[info[3] + 0x10:info[3] + 0x10 + 0x290] = backup

        backupA = bytes(data[info[3] + 0x40:info[3] + 0x40 + 144])
        decrypt_data5(data, info[3] + 0x40, 144)
        ep_A   = u32(data, info[3] + 0x40)
        dirs_A = bytes(data[info[3] + 0x50:info[3] + 0x50 + 128])
        data[info[3] + 0x40:info[3] + 0x40 + 144] = backupA

        data[info[3]:info[3] + 0x300] = live_meta   # restore program tail (overlap)

        # Restore the protected file's PE header into the live image so that
        # section bookkeeping operates on a known-good copy.
        data[:0x1000] = file_data[:0x1000]
        exe_pe = u32(data, 60)
        opt_hdr_size = u16(file_data, pe_header + 20)
        sec_hdr_base = pe_header + 24 + opt_hdr_size
        image_size = u32(file_data, pe_header + 80)

        # Pick layout. Layout B is the modern shell default. Prefer it whenever
        # its EP is non-garbage (anything within image, including 0 - some
        # SEGA system components have their EP zeroed by CrackProof and we
        # patch a stub EP from the mscoree IAT later). Fall back to Layout A
        # only if the Layout-B EP is out of bounds.
        if 0 <= ep_B < image_size:
            original_ep, dirs, layout = ep_B, dirs_B, 'B'
        elif 0 < ep_A < image_size:
            original_ep, dirs, layout = ep_A, dirs_A, 'A'
        elif ss_size == 0x10C8:
            original_ep, dirs, layout = ep_A, dirs_A, 'A(ss)'
        else:
            original_ep, dirs, layout = ep_B, dirs_B, 'B(ss)'

        # Replace the data directories with the chosen layout's view.
        data[exe_pe + 0x88:exe_pe + 0x88 + 128] = dirs

        # Pick Import RVA candidate. The metadata's import dir is the truth for
        # most amdaemon samples; for some SEGA system components the metadata
        # leaves it zero and the anchor stage's value is the only one we have.
        def _idt_plausible(rva, size):
            if not (0x1000 < rva < image_size and 0 < size < 0x10000):
                return False
            return u32(data, rva + 12) != 0  # NameRVA non-zero

        cand_b = (struct.unpack_from('<II', dirs_B, 8))   # dirs_B[1]
        cand_a = (struct.unpack_from('<II', dirs_A, 8))   # dirs_A[1]
        cand_anchor = (saved_import_rva, saved_import_size)

        import_rva_final, import_size_final = 0, 0
        for rva, sz in (cand_b, cand_a, cand_anchor):
            if _idt_plausible(rva, sz):
                import_rva_final, import_size_final = rva, sz
                break
        # Even if no candidate validates, fall back to the anchor value so that
        # the loader at least sees a non-zero pointer (rare edge case).
        if import_rva_final == 0 and saved_import_rva:
            import_rva_final, import_size_final = saved_import_rva, saved_import_size

        def _valid_reloc_dir(rva, size):
            if not (rva and size and rva + size <= len(data)):
                return False
            pos = rva
            end = rva + size
            blocks = 0
            entries = 0
            while pos + 8 <= end:
                page = u32(data, pos)
                block_size = u32(data, pos + 4)
                if page == 0 and block_size == 0:
                    break
                if block_size < 8 or block_size % 4 != 0 or pos + block_size > end:
                    return False
                count = (block_size - 8) // 2
                if count == 0 or page >= image_size or page & 0xFFF:
                    return False
                for entry_idx in range(count):
                    reloc_type = u16(data, pos + 8 + entry_idx * 2) >> 12
                    if reloc_type not in (0, 3, 10):
                        return False
                blocks += 1
                entries += count
                pos += block_size
            return blocks > 0 and entries > 0

        reloc_rva = u32(dirs, 5 * 8)
        reloc_size = u32(dirs, 5 * 8 + 4)
        has_valid_reloc = _valid_reloc_dir(reloc_rva, reloc_size)

        # Set entry point (0 is legal: TLS-only / SEGA system component).
        w32(data, exe_pe + 40, original_ep)
        # Write the chosen Import RVA into the PE header.
        w32(data, exe_pe + 0x90, import_rva_final)
        w32(data, exe_pe + 0x94, import_size_final)
        if has_valid_reloc:
            w32(data, exe_pe + 0xB0, reloc_rva)
            w32(data, exe_pe + 0xB4, reloc_size)
            w16(data, exe_pe + 94, u16(file_data, pe_header + 94))
        print(f'  Layout {layout}: EP=0x{original_ep:X}, Import RVA=0x{import_rva_final:X}/{import_size_final:X}')
        if has_valid_reloc:
            print(f'  BaseReloc restored: RVA=0x{reloc_rva:X} Size=0x{reloc_size:X}')

        # ---- .NET MetaData restore (CrackProof leaves it unencrypted) ----
        # For .NET assemblies, CrackProof preserves the COR20 header + BSJB
        # MetaData section in the protected file at their original RVA-mapped
        # offsets - these regions are NOT covered by Stage 8 decompression.
        # If the CLR data directory is non-zero, copy these regions verbatim
        # from the protected file so DIE etc. can identify the assembly and
        # mscoree._CorExeMain can find valid metadata.
        clr_rva  = u32(data, exe_pe + 0xF8)
        clr_size = u32(data, exe_pe + 0xFC)

        def _prot_rva_to_off(rva):
            """Map RVA -> file offset using the protected file's section table."""
            nsec = u16(file_data, pe_header + 6)
            opt  = u16(file_data, pe_header + 20)
            tab  = pe_header + 24 + opt
            for i in range(nsec):
                s = tab + i * 40
                va = u32(file_data, s + 12)
                vs = u32(file_data, s + 8)
                rsz = u32(file_data, s + 16)
                rp = u32(file_data, s + 20)
                if va <= rva < va + max(vs, rsz):
                    return rp + (rva - va)
            return None

        # A cross-layout REPACK (trailer present) embeds the FINAL plaintext program,
        # so the COR20/BSJB metadata is already reconstructed by the file-decode loop;
        # copying it again from the (re-)packed file reads the wrong bytes. Only do the
        # verbatim restore for ORIGINAL CrackProof samples.
        if _tgt_hdr is None and clr_rva and clr_size and clr_rva + clr_size <= len(data):
            cor_off = _prot_rva_to_off(clr_rva)
            if cor_off is not None and cor_off + 0x48 <= len(file_data):
                # Verify it's a real COR20 header (cb field == 0x48).
                if u32(file_data, cor_off) == 0x48:
                    data[clr_rva:clr_rva + 0x48] = file_data[cor_off:cor_off + 0x48]
                    md_rva  = u32(data, clr_rva + 0x08)
                    md_size = u32(data, clr_rva + 0x0C)
                    print(f'  .NET COR20 restored @ RVA=0x{clr_rva:X} MetaData=(0x{md_rva:X}, 0x{md_size:X})')
                    if md_rva and md_size and md_rva + md_size <= len(data):
                        md_off = _prot_rva_to_off(md_rva)
                        if md_off is not None and md_off + md_size <= len(file_data):
                            if file_data[md_off:md_off + 4] == b'BSJB':
                                data[md_rva:md_rva + md_size] = file_data[md_off:md_off + md_size]
                                print(f'  .NET BSJB MetaData restored @ RVA=0x{md_rva:X} size=0x{md_size:X}')
                    resources_rva = u32(data, clr_rva + 0x18)
                    resources_size = u32(data, clr_rva + 0x1C)
                    if resources_rva and resources_size and resources_rva + resources_size <= len(data):
                        resources_off = _prot_rva_to_off(resources_rva)
                        if resources_off is not None and resources_off + resources_size <= len(file_data):
                            current_resources = data[resources_rva:resources_rva + resources_size]
                            protected_resources = file_data[resources_off:resources_off + resources_size]
                            if not any(current_resources) and any(protected_resources):
                                data[resources_rva:resources_rva + resources_size] = protected_resources
                                print(f'  .NET Resources restored @ RVA=0x{resources_rva:X} size=0x{resources_size:X}')

        # ---- Section table fixup ----
        export_va   = u32(clean_file_data, pe_header + 24 + opt_hdr_size - 128)
        export_size = u32(clean_file_data, pe_header + 24 + opt_hdr_size - 124)
        export_file_off = 0
        text_off = 0
        text_size = 0
        sec_hdr = sec_hdr_base
        while u32(file_data, sec_hdr + 8) != 0:
            va    = u32(file_data, sec_hdr + 12)
            sz    = u32(file_data, sec_hdr + 8)
            f_off = u32(file_data, sec_hdr + 20)
            sec_name = file_data[sec_hdr:sec_hdr + 8]
            if sec_name[:5] == b'.text':
                text_off, text_size = va, sz
            if export_va >= va and export_va + export_size <= va + sz:
                export_file_off = export_va - va + f_off
            # SizeOfRawData = VirtualSize, PointerToRawData = VirtualAddress
            w32(data, sec_hdr + 16, sz)
            w32(data, sec_hdr + 20, va)
            # .rdata becomes RW so the loader can write the resolved IAT.
            if sec_name[:6] == b'.rdata':
                w32(data, sec_hdr + 36, 0xC0000040)
            sec_hdr += 40

        if export_size != 0 and export_file_off != 0:
            data[export_va:export_va + export_size] = file_data[export_file_off:export_file_off + export_size]
            print(f'  Restored export table at 0x{export_va:X}')

        # ---- .text decrypt_data8 (EXE only) -----------------------------
        # DLL samples already contain final .text after file decompression;
        # running decrypt_data8 on their DllMain corrupts code and makes the
        # loader fail with ERROR_DLL_INIT_FAILED.
        is_dll = (u16(data, exe_pe + 22) & 0x2000) != 0
        _skip_d8 = _tgt_hdr is not None and (_tgt_hdr.get('flags', 0) & 1)
        if is_dll:
            print('  decrypt_data8: DLL image, skipping')
        if _skip_d8:
            print('  decrypt_data8: skipped (cross-layout repack carries final plaintext .text)')
        if (not _skip_d8) and (not is_dll) and text_size > 0 and text_off > 0 and text_off <= original_ep < text_off + text_size:
            def _apply_d8_page(buf, t_off, page_idx, key_formula):
                pk = key_formula(page_idx)
                pa = t_off + page_idx * 0x1000
                k = pk
                k = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
                for bi in range(1, 256):
                    rk = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
                    ri = (rk + bi) & 0xFFFFFFFF
                    k = (ri + bi) & 0xFFFFFFFF
                    tidx = pa + bi * 16 + (ri & 0xF)
                    buf[tidx] = (buf[tidx] ^ k) & 0xFF

            # Auto-detect formula by checking which decrypt_data8 mutations
            # land on 0xCC (compiler int3 padding) bytes. Counting 0xCC across
            # the whole page is too noisy because most page bytes are not
            # mutated. Instead we look at ONLY the 255 byte positions that
            # decrypt_data8 modifies per page and ask: "did the formula turn
            # this byte into 0xCC?" - the correct formula should hit int3 pads
            # disproportionately often.
            num_pages_total = text_size // 0x1000
            sample_pages = []
            for frac in (0.25, 0.5, 0.75):
                pg = int(num_pages_total * frac)
                if 0 < pg < num_pages_total:
                    sample_pages.append(pg)
            if not sample_pages and num_pages_total > 1:
                sample_pages = [num_pages_total // 2]

            def _score_formula(ffunc):
                """For each sample page, count how many decrypt_data8-mutated
                positions become 0xCC after applying the formula."""
                hits = 0
                for sp in sample_pages:
                    pg_off = text_off + sp * 0x1000
                    src = data[pg_off:pg_off + 0x1000]
                    if ffunc is None:
                        # Baseline: how many of the would-be-mutated positions
                        # are already 0xCC without any decryption?
                        k = 1  # any non-zero so positions are reachable
                        k = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
                        # But we want to test the *positions* the real formula
                        # would target. Without a real key we can't know them,
                        # so for 'none' we use a uniform sample of positions:
                        for bi in range(1, 256):
                            tidx = bi * 16  # use first byte of each block
                            if tidx < len(src) and src[tidx] == 0xCC:
                                hits += 1
                        continue
                    k = ffunc(sp)
                    k = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
                    for bi in range(1, 256):
                        rk = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
                        ri = (rk + bi) & 0xFFFFFFFF
                        k = (ri + bi) & 0xFFFFFFFF
                        tidx = bi * 16 + (ri & 0xF)
                        if tidx < len(src):
                            mutated = src[tidx] ^ (k & 0xFF)
                            if mutated == 0xCC:
                                hits += 1
                return hits

            none_hits = _score_formula(None)
            best_score, best_name, best_formula = none_hits, 'none', None
            for fname, ffunc in (
                ('page+1', lambda p: p + 1),
                ('0x8000*(page+1)', lambda p: 0x8000 * (p + 1)),
            ):
                hits = _score_formula(ffunc)
                if hits > best_score:
                    best_score, best_name, best_formula = hits, fname, ffunc

            # If best formula doesn't clearly outscore the baseline by at
            # least 2x, treat .text as already plaintext (no decrypt_data8).
            # On real Layout-A samples the correct formula scores ~3-10x
            # the baseline; on already-plaintext samples the formulas are
            # statistical noise around the baseline.
            if best_formula is not None and best_score < none_hits * 2:
                print(f'  decrypt_data8 skipped: best={best_name} hits={best_score} '
                      f'vs none={none_hits} (<2x baseline, already plaintext)')
                best_formula = None

            if best_formula is not None:
                num_pages = text_size // 0x1000
                for pg in range(num_pages):
                    _apply_d8_page(data, text_off, pg, best_formula)
                print(f'  decrypt_data8 ({best_name}, 0xCC score={best_score}): {num_pages} pages')
            else:
                print(f'  decrypt_data8: skipped (.text already decoded, 0xCC score={best_score})')

        # ---- decrypt_data7 on DLL/function names + IAT range -----------
        # The packer obfuscates import-name strings (genuine CrackProof format),
        # so this de-obfuscation is required for BOTH original samples and
        # cross-layout repacks (SEGA: every DLL, .NET: kernel32). The IDT is
        # terminated by a null entry (name_rva == 0), NOT by the directory size
        # field, which many linkers under-declare. The .NET runaway walk that
        # used to scribble decrypt_data7 over the header was caused by the
        # COR20/BSJB restore clobbering the IDT's null terminator; that restore
        # is now gated off for repacks (see above), so the IDT stays
        # null-terminated and the standard name_rva == 0 stop is sufficient.
        dll_count = 0
        iat_min, iat_max = 0xFFFFFFFF, 0
        if import_rva_final:
            pos = import_rva_final
            while pos + 20 <= len(data):
                name_rva = u32(data, pos + 12)
                if name_rva == 0:
                    break
                if name_rva >= len(data):
                    break
                # Decrypt the DLL name unless it already reads as a clean
                # plain-ASCII *.dll / *.exe string (some samples ship the IDT
                # in plain text already - e.g. SEGA system components).
                end = data.find(b'\x00', name_rva, name_rva + 64)
                already_plain = False
                if end > name_rva and end - name_rva <= 60:
                    s = bytes(data[name_rva:end])
                    if all(0x20 <= b < 0x7F for b in s):
                        low = s.lower()
                        if low.endswith(b'.dll') or low.endswith(b'.exe'):
                            already_plain = True
                if not already_plain:
                    decrypt_data7(data, name_rva, name_rva & 0xFF)
                # Normalize to lowercase: 'KeRnEl32.dLl' -> 'kernel32.dll'.
                end = data.find(b'\x00', name_rva, name_rva + 64)
                if end > name_rva:
                    s = bytes(data[name_rva:end])
                    if all(0x20 <= b < 0x7F for b in s):
                        data[name_rva:end] = s.lower()

                oft = u32(data, pos)
                ift = u32(data, pos + 16)
                thunk = oft if oft else ift
                if 0 < ift < len(data):
                    iat_min = min(iat_min, ift)

                while thunk and thunk + 8 <= len(data):
                    v = u64(data, thunk)
                    if v == 0:
                        break
                    if not (v & 0x8000000000000000):
                        r = v & 0xFFFFFFFF
                        if r + 2 < len(data):
                            # Decrypt unless the function name reads as plain ASCII.
                            fend = data.find(b'\x00', r + 2, r + 2 + 256)
                            already = False
                            if fend > r + 2 and fend - (r + 2) <= 250:
                                fs = bytes(data[r + 2:fend])
                                if all(0x20 <= b < 0x7F for b in fs):
                                    already = True
                            if not already:
                                decrypt_data7(data, r + 2, r & 0xFF)
                                w16(data, r, 0)
                    thunk += 8
                if 0 < ift < len(data):
                    tp = ift
                    while tp + 8 <= len(data):
                        v2 = u64(data, tp)
                        tp += 8
                        if v2 == 0:
                            break
                    iat_max = max(iat_max, tp)
                dll_count += 1
                pos += 20

            if import_size_final == 0:
                import_size_final = (dll_count + 1) * 20
                w32(data, exe_pe + 0x94, import_size_final)
            if iat_min < iat_max:
                w32(data, exe_pe + 0xE8, iat_min)
                w32(data, exe_pe + 0xEC, iat_max - iat_min)

            # CrackProof zeroes the original EP for some SEGA system components
            # (sgxsegaboot.exe / sgosupdate.exe) that look .NET-stubbed
            # (mscoree import + COR20 dir). The metadata stores EP == 0 which
            # the PE loader rejects with STATUS_INVALID_IMAGE_FORMAT for GUI
            # EXEs. We patch a 6-byte `jmp [mscoree IAT slot]` stub at the
            # start of .text (Stage 8 leaves that region zero-filled) and
            # point EP at the stub so the loader can dispatch to
            # mscoree._CorExeMain. Combined with the cleared COR20 dir below,
            # _CorExeMain returns cleanly when it sees no managed metadata.
            if original_ep == 0:
                # Find the mscoree IAT slot RVA.
                mscoree_iat = 0
                pos = import_rva_final
                while pos + 20 <= len(data):
                    n_rva = u32(data, pos + 12)
                    if n_rva == 0:
                        break
                    nm = data[n_rva:n_rva + 32].split(b'\x00', 1)[0]
                    if nm.lower() == b'mscoree.dll':
                        mscoree_iat = u32(data, pos + 16)
                        break
                    pos += 20

                if mscoree_iat:
                    # Locate the .text section RVA/size.
                    sec = sec_hdr_base
                    text_rva, text_vs = 0, 0
                    while u32(file_data, sec + 8) != 0:
                        if file_data[sec:sec + 5] == b'.text':
                            text_vs   = u32(file_data, sec + 8)
                            text_rva  = u32(file_data, sec + 12)
                            break
                        sec += 40
                    # Stub: FF 25 disp32 -> jmp qword ptr [mscoree_iat]
                    if text_rva and text_vs > 6:
                        stub_off = text_rva
                        disp32 = (mscoree_iat - (stub_off + 6)) & 0xFFFFFFFF
                        data[stub_off:stub_off + 2] = b'\xFF\x25'
                        struct.pack_into('<I', data, stub_off + 2, disp32)
                        w32(data, exe_pe + 40, stub_off)
                        original_ep = stub_off
                        print(f'  EP=0 -> .text+0x0 jump stub -> mscoree IAT @ 0x{mscoree_iat:X}')

        # CrackProof's metadata sometimes leaves a fake CLR (COR20) directory
        # entry pointing at a never-populated header (cb == 0). If we leave it
        # in place, the PE loader treats the image as a managed assembly and
        # hands control to mscoree._CorExeMain, which then crashes reading
        # the empty header (STATUS_DLL_INIT_FAILED). Clearing the directory
        # makes the loader treat the image as native and call our EP stub
        # instead.
        cor20_dir_off = exe_pe + 0xF8
        cor20_rva = u32(data, cor20_dir_off)
        if cor20_rva and cor20_rva + 4 <= len(data):
            if u32(data, cor20_rva) == 0:
                w32(data, cor20_dir_off, 0)
                w32(data, cor20_dir_off + 4, 0)

        # Same defensive cleanup for the TLS directory. When metadata stores
        # a TLS dir RVA whose IMAGE_TLS_DIRECTORY64 target is zero-filled
        # (RawStart/End/Index/Callbacks all 0), the PE loader's
        # LdrpAllocateTlsEntry dereferences NULL during process init and
        # raises STATUS_ACCESS_VIOLATION (0xC0000005) before EP runs.
        # Observed on sgxmaster.exe variants. Clearing the directory makes
        # the loader skip static-TLS handling.
        tls_dir_off = exe_pe + 0xD0
        tls_rva = u32(data, tls_dir_off)
        if tls_rva and tls_rva + 24 <= len(data):
            raw_start = u64(data, tls_rva)
            raw_end   = u64(data, tls_rva + 8)
            cb_addr   = u64(data, tls_rva + 16)
            if raw_start == 0 and raw_end == 0 and cb_addr == 0:
                w32(data, tls_dir_off, 0)
                w32(data, tls_dir_off + 4, 0)

        print(f'  Total: {dll_count} DLLs, Import RVA=0x{import_rva_final:X} Size=0x{import_size_final:X}')

        # Subsystem is kept from the protected PE header. Relocations are
        # kept only when metadata points at a valid relocation block table;
        # otherwise clear them because some CrackProof metadata points into
        # shell bookkeeping rather than real IMAGE_BASE_RELOCATION data.
        if not has_valid_reloc:
            w16(data, exe_pe + 94, 0)
            w32(data, exe_pe + 0xB0, 0)
            w32(data, exe_pe + 0xB4, 0)

        # ---- Write output ----
        if _tgt_hdr is not None:
            _apply_target_hdr(data, _tgt_hdr)
            print(f'  [+] rebuilt final PE header from cross-layout trailer '
                  f'(nsec={_tgt_hdr["nsec"]}, SizeOfImage=0x{_tgt_hdr["simg"]:X}, '
                  f'output 0x{len(data):X} bytes)')
        dot = in_file.rfind('.')
        out_file = in_file[:dot] + '.unpack' + in_file[dot:] if dot >= 0 else in_file + '.unpack'
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
    print(f'  key_offsets = [{", ".join(f"0x{ko:08X}" for ko in key_offsets)}]')

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
    print(f'  sevenStart = 0x{seven_start_actual:X}, sevenDsz = 0x{seven_dsz:X}')
    # Find LFSR block in sevenStage (scan backward from middle, like PE32+)
    scan_start = max(0, seven_dsz // 2)
    custom_dec_off = find_lfsr_block(data, seven_start_actual, seven_dsz, scan_start, scan_backward=True)
    if custom_dec_off is None:
        # Fallback: forward scan
        custom_dec_off = find_lfsr_block(data, seven_start_actual, seven_dsz, 0)
    if custom_dec_off is None:
        print('ERROR: could not locate customDecryptor in sevenStage')
        return
    custom_dec_addr = seven_start_actual + custom_dec_off
    print(f'  customDecryptor at seven+0x{custom_dec_off:X}')
    decrypt_data6(data, custom_dec_addr)
    custom_dec = generate_custom_decryptor(data, custom_dec_addr)
    if custom_dec is None:
        return

    # PE32: eighthStageKey — brute-force search (like PE32+ path)
    seven_cs = checksum_with_size_xor(data, seven_stage_cs_addr)
    eighth_addr = dp_base + 0xC0
    eighth_dsz = u32(data, eighth_addr + 12)
    eighth_src = u32(data, eighth_addr)
    eighth_ssz = u32(data, eighth_addr + 4)
    eighth_backup = bytearray(data[eighth_src:eighth_src + eighth_ssz])
    eighth_pair_bak = bytearray(data[eighth_addr:eighth_addr + 16])

    # Build candidate list: try known gap from end, then gap from customDecryptor
    eighth_key_candidates = []
    for end_gap in [0xD0, 0xC0, 0xE0, 0xB0, 0xA0, 0xF0, 0x100]:
        off = seven_dsz - end_gap
        if 0 <= off < seven_dsz:
            val = u32(data, seven_start_actual + off)
            if val != 0 and val != 0xCCCCCCCC:
                eighth_key_candidates.append(off)
    for gap in [0x70, 0xD0, 0x28, 0x50, 0x48, 0x30, 0x40, 0x58, 0x60, 0x20, 0x38, 0x80, 0x90, 0xA0, 0xB0]:
        off = custom_dec_off - gap
        if off >= 0 and off + 4 <= seven_dsz and off not in eighth_key_candidates:
            val = u32(data, seven_start_actual + off)
            if val != 0 and val != 0xCCCCCCCC:
                eighth_key_candidates.append(off)
    # Scan region before customDecryptor
    for off in range(max(0, custom_dec_off - 0x100), custom_dec_off, 4):
        if off not in eighth_key_candidates:
            val = u32(data, seven_start_actual + off)
            if val != 0 and val != 0xCCCCCCCC and not all(32 <= ((val >> (i*8)) & 0xFF) < 127 for i in range(4)):
                eighth_key_candidates.append(off)

    eighth_key_success = False
    for ek_off in eighth_key_candidates:
        data[eighth_src:eighth_src + eighth_ssz] = eighth_backup[:]
        data[eighth_addr:eighth_addr + 16] = eighth_pair_bak[:]
        test_key = u32(data, seven_start_actual + ek_off)
        test_key = advance_key(test_key, 3)
        fk8 = (header_checksum ^ fifth_cs ^ seven_cs ^ test_key) & 0xFFFFFFFF
        try:
            result = decrypt_and_decompress(data, eighth_addr, fk8, key_offsets, custom_dec, verbose=False)
            if result:
                eighth_start_test = u32(data, eighth_addr)
                if 0x1000 < eighth_start_test < len(data):
                    print(f'  eighthStageKey at seven+0x{ek_off:X}, raw=0x{u32(data, seven_start_actual + ek_off):08X}')
                    print(f'  eighthStage key = 0x{fk8:08X}')
                    eighth_key_success = True
                    break
        except:
            pass
    if not eighth_key_success:
        print('ERROR: could not find valid eighthStageKey in sevenStage')
        return

    eighth_start = u32(data, eighth_addr)
    print(f'  eighthStageStart = 0x{eighth_start:08X}, dsz = 0x{eighth_dsz:X}')

    # ---- Final processing (PE32) ----
    off_import_table = 0x3C50 + ss_shift
    off_file_cs      = 0x3C68 + ss_shift
    off_compressed_info = 0x3C78 + ss_shift
    off_zero_list    = 0x3C80 + ss_shift
    off_file_lfsr    = 0x40EC + ss_shift
    print(f'\n=== Final: File data decryption (PE32) ===')

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

    # File decryptor — validate LFSR at expected offset, fallback to scan
    lfsr_off = off_file_lfsr
    # Check exact offset first
    lfsr_found = find_lfsr_block(data, eighth_start, eighth_dsz, lfsr_off)
    if lfsr_found == lfsr_off:
        pass  # exact offset is valid
    else:
        # Scan all candidates from off_zero_list, pick closest to off_file_lfsr
        valid_opcodes = {0x04, 0x2C, 0x34, 0x90, 0xC0, 0xC3, 0xFE}
        lfsr_candidates = []
        for scan_off in range(off_zero_list, eighth_dsz - 95):
            abs_off = eighth_start + scan_off
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
                lfsr_candidates.append(scan_off)
        if lfsr_candidates:
            # The real file LFSR lives at or just *before* off_file_lfsr in every
            # observed sample (delta in {0, -0x20}). False positives (other LFSR
            # blocks used elsewhere) sit after it with a smaller |delta|, which
            # the legacy "closest absolute" rule misses. Prefer exact, then the
            # smallest negative delta, fall back to the smallest positive.
            exact = [c for c in lfsr_candidates if c == off_file_lfsr]
            negatives = sorted([c for c in lfsr_candidates if c < off_file_lfsr],
                               key=lambda c: off_file_lfsr - c)
            positives = sorted([c for c in lfsr_candidates if c > off_file_lfsr],
                               key=lambda c: c - off_file_lfsr)
            if exact:
                lfsr_off = exact[0]
            elif negatives:
                lfsr_off = negatives[0]
            else:
                lfsr_off = positives[0]
            print(f'  fileLFSR adjusted: eighth+0x{lfsr_off:X} (expected 0x{off_file_lfsr:X}, {len(lfsr_candidates)} candidates)')
        else:
            print('ERROR: could not locate file LFSR in eighthStage')
            return
    print(f'  fileLFSR at eighth+0x{lfsr_off:X}')
    file_dec_addr = eighth_start + lfsr_off
    decrypt_data6(data, file_dec_addr)
    file_dec = generate_custom_decryptor(data, file_dec_addr)
    if file_dec is None:
        return

    # ---- PE32 metadata: EP and data dirs from info[3] ----
    test_val = u32(data, info[3] + 0x10)
    metadata_ep = None
    metadata_dirs = None  # 128 bytes of data directories (16 entries × 8 bytes)

    if test_val > 0x10000:
        # Layout B: decrypt info[3]+0x10 (0x290 bytes), EP at +0x20, data dirs at +0x30
        backup_meta = bytes(data[info[3] + 0x10:info[3] + 0x10 + 0x290])
        decrypt_data5(data, info[3] + 0x10, 0x290)
        metadata_ep = u32(data, info[3] + 0x20)
        metadata_dirs = bytes(data[info[3] + 0x30:info[3] + 0x30 + 128])
        print(f'  Metadata Layout B: EP=0x{metadata_ep:X}')
        data[info[3] + 0x10:info[3] + 0x10 + 0x290] = backup_meta
    else:
        # Layout A: decrypt info[3]+0x40 (144 bytes), EP at +0x40, data dirs at +0x50
        backup_meta = bytes(data[info[3] + 0x40:info[3] + 0x40 + 144])
        decrypt_data5(data, info[3] + 0x40, 144)
        metadata_ep = u32(data, info[3] + 0x40)
        metadata_dirs = bytes(data[info[3] + 0x50:info[3] + 0x50 + 128])
        print(f'  Metadata Layout A: EP=0x{metadata_ep:X}')
        data[info[3] + 0x40:info[3] + 0x40 + 144] = backup_meta

    # Save PE header values before file_data copy (fallback if metadata fails)
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
        if s_sz2 == 0: break
        file_src = src2 + compress_data_offset
        data[dst2:dst2 + s_sz2] = clean_file_data[file_src:file_src + s_sz2]
        aes_decrypt(data, dst2, s_sz2, key_offsets[2])
        _lut, _tt = file_dec
        data[dst2:dst2 + s_sz2] = bytearray(bytes(data[dst2:dst2 + s_sz2]).translate(_tt))
        if s_sz2 != d_sz2:
            decompress(data, dst2, dst2, key_offsets[0], s_sz2, d_sz2)
        block_count += 1
    print(f'  Decrypted {block_count} data blocks')

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
        # .idata needs RW for IAT (loader writes resolved addresses)
        if sec_name[:6] == b'.idata':
            w32(data, sec_hdr + 36, 0xC0000040)
        sec_hdr += 40
    if export_size != 0 and export_file_off != 0:
        data[export_va:export_va + export_size] = file_data[export_file_off:export_file_off + export_size]

    # .text decrypt with decrypt_data8 (PE32: auto-detect key formula)
    if text_size > 0 and text_off > 0:
        def _d8_page(buf, t_off, pg, pk):
            pa = t_off + pg * 0x1000
            k = pk
            rk = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
            k = rk
            for bi in range(1, 256):
                rk = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
                ri = (rk + bi) & 0xFFFFFFFF
                k = (ri + bi) & 0xFFFFFFFF
                tidx = pa + bi * 16 + (ri & 0xF)
                buf[tidx] = (buf[tidx] ^ k) & 0xFF

        # Auto-detect key formula by counting 0xCC (int3 padding) on interior code pages.
        # Correct decryption produces many 0xCC bytes (function alignment padding);
        # wrong formula corrupts them. Sample pages at 25%, 50%, 75% of .text.
        num_pages_total = text_size // 0x1000
        sample_pages = []
        for frac in (0.25, 0.5, 0.75):
            pg = int(num_pages_total * frac)
            if 0 < pg < num_pages_total:
                sample_pages.append(pg)
        if not sample_pages and num_pages_total > 1:
            sample_pages = [num_pages_total // 2]

        formulas = [
            ('page+1', lambda p: p + 1),
            ('0x8000*(page+1)', lambda p: 0x8000 * (p + 1)),
        ]
        best_score = -1
        best_name = 'none'
        best_func = None
        for fname, ffunc in formulas:
            total_cc = 0
            for sp in sample_pages:
                test_buf = bytearray(data[text_off + sp * 0x1000: text_off + (sp + 1) * 0x1000])
                # Apply decrypt_data8 to this single page (using local offsets)
                pa = 0
                k = ffunc(sp)
                rk = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
                k = rk
                for bi in range(1, 256):
                    rk = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
                    ri = (rk + bi) & 0xFFFFFFFF
                    k = (ri + bi) & 0xFFFFFFFF
                    tidx = pa + bi * 16 + (ri & 0xF)
                    if tidx < len(test_buf):
                        test_buf[tidx] = (test_buf[tidx] ^ k) & 0xFF
                total_cc += test_buf.count(0xCC)
            if total_cc > best_score:
                best_score = total_cc
                best_name = fname
                best_func = ffunc
        if sample_pages:
            print(f'  decrypt_data8 auto-detect: {best_name} (0xCC score={best_score} on {len(sample_pages)} sample pages)')

        if best_func is not None:
            print(f'\n=== Decrypting .text with decrypt_data8 ({best_name}) ===')
            num_pages = text_size // 0x1000
            for page in range(num_pages):
                _d8_page(data, text_off, page, best_func(page))
            print(f'  Decrypted {num_pages} pages')
        else:
            print(f'  decrypt_data8: no formula detected, skipping')

    # Fix data directories (PE32: data dirs start at pe+0x78, not pe+0x88)
    exe_pe = u32(data, 60)
    if metadata_dirs is not None:
        for i in range(128):
            data[exe_pe + 0x78 + i] = metadata_dirs[i]
    else:
        w32(data, exe_pe + 0x80, saved_pe80)
        w32(data, exe_pe + 0x88, saved_pe88)
        w32(data, exe_pe + 0x8C, saved_pe8c)
    # Clear BaseReloc directory (PE32: index 5 = pe+0xA0)
    w32(data, exe_pe + 0xA0, 0)
    w32(data, exe_pe + 0xA4, 0)
    # PE32: clear DllCharacteristics
    w16(data, exe_pe + 0x5E, 0)

    # Fix TLS directory (PE32: index 9 = pe+0xC0)
    # CrackProof doesn't decompress the TLS directory structure in .rdata,
    # so it stays all zeros. If AddressOfIndex==0, the loader will write to
    # NULL causing 0xC0000005. We reconstruct the TLS structure from section info.
    tls_dir_rva = u32(data, exe_pe + 0xC0)
    tls_dir_sz  = u32(data, exe_pe + 0xC4)
    if tls_dir_rva > 0 and tls_dir_sz >= 24 and tls_dir_rva + 24 <= len(data):
        tls_vals = struct.unpack_from('<6I', data, tls_dir_rva)
        if all(v == 0 for v in tls_vals):
            # TLS directory contents are cleared in the CrackProof final image.
            image_base = u32(data, exe_pe + 52)

            # Preferred path: recover the ORIGINAL 24-byte TLS directory and its
            # declared template from the protected source PE. CrackProof leaves a
            # valid TLS dir RVA but zeroes its contents; synthesizing a fresh dir
            # (fallback below) redirects AddressOfIndex to scratch space, yet the
            # program's own code still selects TLS slots through its original index
            # variable (referenced from hundreds of functions). The Windows loader
            # then initialises a different variable than the one runtime code reads,
            # and the thread-state mismatch causes timing-dependent heap corruption
            # (STATUS_HEAP_CORRUPTION, 0xC0000374). Restoring the original loader
            # state from the source PE keeps index/callbacks/template intact.
            def _prot_rva_to_off_pe32(rva):
                """Map an RVA to a file offset via the protected PE's section table."""
                _pns = u16(file_data, pe_header + 6)
                _popt = u16(file_data, pe_header + 20)
                _ptab = pe_header + 24 + _popt
                for _pi in range(_pns):
                    _ps = _ptab + _pi * 40
                    _pva = u32(file_data, _ps + 12)
                    _pvs = u32(file_data, _ps + 8)
                    _prsz = u32(file_data, _ps + 16)
                    _prp = u32(file_data, _ps + 20)
                    if _pva <= rva < _pva + max(_pvs, _prsz):
                        return _prp + (rva - _pva)
                return None

            def _restore_original_tls():
                dir_off = _prot_rva_to_off_pe32(tls_dir_rva)
                if dir_off is None or dir_off + 24 > len(file_data):
                    return False
                directory = bytes(file_data[dir_off:dir_off + 24])
                start = struct.unpack_from('<I', directory, 0)[0]
                end   = struct.unpack_from('<I', directory, 4)[0]
                # StartAddressOfRawData/EndAddressOfRawData are VAs; derive the
                # template's RVA + size and require a sane ordering.
                if start < image_base or end < start:
                    return False
                template_rva  = start - image_base
                template_size = end - start
                template_off  = _prot_rva_to_off_pe32(template_rva)
                if template_off is None or template_off + template_size > len(file_data):
                    return False
                if template_rva + template_size > len(data):
                    return False
                # Restore the directory verbatim, then copy the declared template
                # (may be empty; the directory alone carries index/callback VAs).
                data[tls_dir_rva:tls_dir_rva + 24] = directory
                if template_size:
                    data[template_rva:template_rva + template_size] = \
                        file_data[template_off:template_off + template_size]
                return True

            if _restore_original_tls():
                print(f'  TLS restored from source PE: '
                      f'Start=0x{u32(data, tls_dir_rva):X} '
                      f'End=0x{u32(data, tls_dir_rva + 4):X} '
                      f'Index=0x{u32(data, tls_dir_rva + 8):X} '
                      f'Callbacks=0x{u32(data, tls_dir_rva + 12):X}')
            else:
                # Fallback: synthesize a minimal empty-TLS loader state when the
                # original state cannot be mapped safely from the source PE.
                # Find .tls and .data sections
                tls_sec_va = 0; data_sec_va = 0; data_sec_sz = 0
                _sh = exe_pe + 24 + u16(data, exe_pe + 20)
                _ns = u16(data, exe_pe + 6)
                for _i in range(_ns):
                    _s = _sh + _i * 40
                    _nm = data[_s:_s+8]
                    _va = u32(data, _s + 12)
                    _sz = u32(data, _s + 16)
                    if _nm[:4] == b'.tls':
                        tls_sec_va = _va
                    if _nm[:5] == b'.data':
                        data_sec_va = _va; data_sec_sz = _sz
                if tls_sec_va > 0 and data_sec_va > 0:
                    # Reconstruct TLS directory
                    start_raw = image_base + tls_sec_va
                    end_raw = start_raw  # Empty TLS data (safe default)
                    # Use last 16 bytes of .data as scratch for TLS index and callbacks
                    # (these bytes are typically zero in BSS area)
                    idx_addr = image_base + data_sec_va + data_sec_sz - 16
                    cb_addr  = image_base + data_sec_va + data_sec_sz - 8
                    # Make sure the scratch area is zeroed
                    data[data_sec_va + data_sec_sz - 16 : data_sec_va + data_sec_sz] = b'\x00' * 16
                    struct.pack_into('<6I', data, tls_dir_rva,
                        start_raw, end_raw, idx_addr, cb_addr, 0, 0x300000)
                    print(f'  TLS synthesized (source recover failed): Start=0x{start_raw:X} End=0x{end_raw:X} Index=0x{idx_addr:X} Cb=0x{cb_addr:X}')
                else:
                    # Can't reconstruct — clear TLS directory to prevent crash
                    w32(data, exe_pe + 0xC0, 0)
                    w32(data, exe_pe + 0xC4, 0)
                    print(f'  TLS cleared (no .tls/.data section found)')

    # Import table (PE32, 4-byte thunks)
    import_table_addr = eighth_start + off_import_table
    import_table_ptr = u32(data, import_table_addr)
    idt_size = u32(data, import_table_addr + 4)
    print(f'  importTable: ptr=0x{import_table_ptr:X}, size=0x{idt_size:X}')

    # Also get import RVA from metadata (data dir index 1)
    metadata_import_rva = 0
    metadata_import_size = 0
    if metadata_dirs is not None:
        metadata_import_rva = _u32.unpack_from(metadata_dirs, 8)[0]
        metadata_import_size = _u32.unpack_from(metadata_dirs, 12)[0]

    # Validate eighthStage import pointer: check first IDT entry
    data_len = len(data)
    eighth_import_valid = False
    if 0 < import_table_ptr < data_len and 0 < idt_size < 0x10000:
        test_name = u32(data, import_table_ptr + 12) if import_table_ptr + 20 <= data_len else 0
        test_ilt = u32(data, import_table_ptr) if import_table_ptr + 4 <= data_len else 0
        if 0x1000 < test_name < data_len and 0x1000 < test_ilt < data_len:
            eighth_import_valid = True

    # Validate metadata import pointer
    metadata_import_valid = False
    if 0x1000 < metadata_import_rva < data_len - 20:
        test_name2 = u32(data, metadata_import_rva + 12)
        test_ilt2 = u32(data, metadata_import_rva)
        if 0x1000 < test_name2 < data_len and 0x1000 < test_ilt2 < data_len:
            metadata_import_valid = True

    # Use the best available import table pointer
    if metadata_import_valid and (not eighth_import_valid or metadata_import_rva != import_table_ptr):
        import_table_ptr = metadata_import_rva
        idt_size = metadata_import_size
    elif not eighth_import_valid:
        print(f'  WARNING: import table invalid!')

    # Process import table: decrypt DLL names and function hint names
    data_len = len(data)
    if 0 < import_table_ptr < data_len and 0 < idt_size < 0x10000:
        idt_pos = import_table_ptr
        idt_end = import_table_ptr + idt_size
        dll_count = 0
        while idt_pos + 20 <= idt_end:
            ilt_rva  = u32(data, idt_pos)
            name_rva = u32(data, idt_pos + 12)
            iat_rva  = u32(data, idt_pos + 16)
            if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                break
            if 0 < name_rva < data_len:
                decrypt_data7(data, name_rva, name_rva & 0xFF)
            thunk_pos = ilt_rva if (0 < ilt_rva < data_len) else iat_rva
            if 0 < thunk_pos < data_len - 4:
                while thunk_pos + 4 <= data_len:
                    thunk_val = u32(data, thunk_pos)
                    if thunk_val == 0: break
                    if not (thunk_val & 0x80000000):
                        if thunk_val + 2 < data_len:
                            decrypt_data7(data, thunk_val + 2, thunk_val & 0xFF)
                            w16(data, thunk_val, 0)
                    thunk_pos += 4
            dll_count += 1
            idt_pos += 20
        print(f'  Decrypted names for {dll_count} DLLs')
    else:
        print(f'  WARNING: import table invalid (ptr=0x{import_table_ptr:X}, size=0x{idt_size:X}), skipping')

    # Update PE header: Import directory (PE32: index 1 = pe+0x80)
    w32(data, exe_pe + 0x80, import_table_ptr)
    w32(data, exe_pe + 0x84, idt_size)

    # Clear IAT directory (PE32: index 12 = pe+0xD8) — match reference behavior
    w32(data, exe_pe + 0xD8, 0)
    w32(data, exe_pe + 0xDC, 0)

    # EP (PE32): use metadata EP from info[3], not packed file header
    if metadata_ep is not None and metadata_ep > 0:
        w32(data, exe_pe + 40, metadata_ep)
        print(f'  EP set to 0x{metadata_ep:X} (from metadata)')
    else:
        # Fallback: use original file EP (likely wrong for CrackProof-protected files)
        real_ep = u32(file_data, pe_header + 40)
        w32(data, exe_pe + 40, real_ep)
        print(f'  WARNING: EP set to 0x{real_ep:X} (from packed file header, may be wrong)')

    # Write output
    dot = in_file.rfind('.')
    if dot >= 0:
        out_file = in_file[:dot] + '.unpack' + in_file[dot:]
    else:
        out_file = in_file + '.unpack'
    print(f'\n=== Writing {out_file} ===')
    if is_pe32:
        if not pe32_imports_already_match_idata_layout(data, pe_header):
            data = move_pe32_imports_to_kmiat(data, pe_header)
        data = compact_memory_image_to_pe(data, pe_header)
    with open(out_file, 'wb') as f:
        f.write(data)
    print(f'Done! {_elapsed()}')


if __name__ == '__main__':
    main()
