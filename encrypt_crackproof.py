"""encrypt_crackproof.py - single-file CrackProof packer / re-packer.

Auto-merged from pack.py + crackproof_repack.py +
crackproof_encrypt_primitives.py + crackproof_lz.py. The only remaining
dependency is the sibling unpacker decrypt_crackproof.py (loaded as `d`),
which is reused to fully unpack the template before re-packing, plus the
bundled stub_profile.bin. AES tables are generated in code when the aes_*
files / aes-dir are absent.

Usage:
  python encrypt_crackproof.py <unpacked.exe>              # pack (default)
  python encrypt_crackproof.py <unpacked.exe> -o out.exe
  python encrypt_crackproof.py extract <packed.exe>        # save stub profile
"""
import argparse
import importlib.util
import pickle
import struct
import sys
import zlib
from pathlib import Path

M = 0xFFFFFFFF
MODULE_PATH = Path(__file__).resolve().parent / 'decrypt_crackproof.py'
DEFAULT_AES_DIR = Path(r'F:\SEGA\DecryptCrackproofDll64')

_spec = importlib.util.spec_from_file_location('decrypt_crackproof_mod', MODULE_PATH)
d = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d)

# Former separate modules collapse into this one. The old e./r./lz. prefixes
# now resolve back to this module namespace so every merged body is unchanged.
class _SelfModule:
    def __getattr__(self, _n): return globals()[_n]
e = r = lz = _SelfModule()

# stub_profile.bin pickles a TemplateProfile whose class used to live in the now
# absorbed crackproof_repack module. Alias the old module names to ourselves so
# pickle.loads resolves crackproof_repack.TemplateProfile (and any siblings) here.
try:
    _THIS_MODULE = sys.modules[__name__]
    for _alias in ('crackproof_repack', 'crackproof_encrypt_primitives',
                   'crackproof_lz'):
        sys.modules.setdefault(_alias, _THIS_MODULE)
except KeyError:
    pass


def w16(b, o, v): struct.pack_into('<H', b, o, v & 0xFFFF)
def w32(b, o, v): struct.pack_into('<I', b, o, v & 0xFFFFFFFF)
def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]



# ======================================================================
# ==== merged from crackproof_lz.py
# ======================================================================



def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


FLAG = 0x8000
MASK = 0x7FFF


def parse_huffman(data, key_off):
    """Invert the decode table at key_off into {symbol: (code_value, code_len)}.
    code_value's bits are emitted LSB-first; reading code_len stream bits LSB
    first routes the decoder to `symbol`."""
    sym2code = {}

    def record(sym, value, length):
        prev = sym2code.get(sym)
        if prev is None or length < prev[1]:
            sym2code[sym] = (value, length)

    def walk(base, bitpos, code):
        for bit in (0, 1):
            off = key_off + (base + bit) * 3
            val = u16(data, off)
            new_code = code | (bit << bitpos)
            if val & FLAG:
                record(val & MASK, new_code, bitpos + 1)
            else:
                walk(val & MASK, bitpos + 1, new_code)

    for i in range(256):
        off = key_off + i * 3
        val = u16(data, off)
        b = data[off + 2]
        if val & FLAG:
            length = b
            record(val & MASK, i & ((1 << length) - 1), length)
        else:
            init_len = b
            walk(val & MASK, init_len, i & ((1 << init_len) - 1))
    return sym2code


class BitWriter:
    """LSB-first bit stream, matching decompress()'s `u32 >> shift` reader."""

    def __init__(self):
        self.buf = bytearray()
        self.nbits = 0

    def write(self, value, length):
        n = self.nbits
        for i in range(length):
            if (n >> 3) >= len(self.buf):
                self.buf.append(0)
            if (value >> i) & 1:
                self.buf[n >> 3] |= 1 << (n & 7)
            n += 1
        self.nbits = n

    def to_bytes(self):
        return bytes(self.buf)


def _emit_count(bw, sym2code, value):
    """Emit 0x100 count-prefix ops so the decoder's `tmp` becomes `value`.
    tmp builds as tmp=(tmp<<8)|byte over the bytes of `value` (MSB first)."""
    if value <= 0:
        return
    bs = []
    v = value
    while v:
        bs.append(v & 0xFF)
        v >>= 8
    bs.reverse()  # MSB first
    for byte in bs:
        bw.write(*sym2code[0x100 | byte])


def _count_bytes(value):
    if value <= 0:
        return ()
    bs = []
    v = value
    while v:
        bs.append(v & 0xFF)
        v >>= 8
    bs.reverse()
    return tuple(bs)


class CompressError(Exception):
    pass


def compress(plaintext, sym2code, max_match=255, window=None):
    """Greedy LZ77 + RLE -> (compressed_bytes, s_size). Guarantees a stream that
    decompress() turns back into `plaintext`. Only uses copy lengths and
    count-prefix bytes actually present in the table, and keeps tmp <= 0xFFFF
    (the decoder rejects a count-prefix op once tmp >= 256). Raises CompressError
    if a literal byte is not encodable (caller should fall back to no-LZ)."""
    import bisect
    n = len(plaintext)
    pt = plaintext
    MAXTMP = 0xFFFF
    valid_copy = sorted(L for L in range(1, 256) if (0x300 | L) in sym2code)
    if not valid_copy:
        valid_copy = []
    valid_prefix = set(b for b in range(256) if (0x100 | b) in sym2code)

    def emittable(v):
        if v == 0:
            return True
        return all(b in valid_prefix for b in _count_bytes(v))

    def snap_down(T):
        k = bisect.bisect_right(valid_copy, T) - 1
        return valid_copy[k] if k >= 0 else 0

    def choose_copy(dist, maxL):
        """largest valid copy length L<=maxL with tmp=dist-L emittable and in range."""
        L = snap_down(maxL)
        while L >= 4:
            tmp = dist - L
            if 0 <= tmp <= MAXTMP and emittable(tmp):
                return L
            L = snap_down(L - 1)
        return 0

    bw = BitWriter()
    index = {}
    i = 0

    def lit(byte):
        code = sym2code.get(0x000 | byte)
        if code is None:
            raise CompressError(f'literal 0x{byte:02X} not in table')
        bw.write(*code)

    def add_index(p):
        if p + 4 <= n:
            index.setdefault(bytes(pt[p:p + 4]), []).append(p)

    have_rle = (0x200 | 1) in sym2code
    while i < n:
        run = 1
        while i + run < n and pt[i + run] == pt[i]:
            run += 1
        best_len = 0
        best_dist = 0
        if valid_copy and i + 4 <= n:
            cands = index.get(bytes(pt[i:i + 4]))
            if cands:
                for pos in reversed(cands[-64:]):
                    dist = i - pos
                    if dist - 4 > MAXTMP:
                        continue
                    maxL = min(max_match, n - i, dist, valid_copy[-1])
                    m = 0
                    while m < maxL and pt[pos + m] == pt[i + m]:
                        m += 1
                    L = choose_copy(dist, m)
                    if L > best_len:
                        best_len = L
                        best_dist = dist
                        if L == valid_copy[-1]:
                            break

        if have_rle and run >= 5:
            lit(pt[i])
            rem = run - 1
            while rem:
                # largest emittable chunk count (c==1 needs no prefix)
                c = min(rem, MAXTMP)
                while c >= 2 and not emittable(c):
                    c -= 1
                _emit_count(bw, sym2code, c if c >= 2 else 0)
                bw.write(*sym2code[0x200 | 1])
                rem -= c
            end = i + run
            while i < end:
                add_index(i)
                i += 1
            continue
        if best_len >= 4:
            _emit_count(bw, sym2code, best_dist - best_len)
            bw.write(*sym2code[0x300 | best_len])
            end = i + best_len
            while i < end:
                add_index(i)
                i += 1
            continue
        lit(pt[i])
        add_index(i)
        i += 1

    comp = bw.to_bytes()
    return comp, len(comp)


# ======================================================================
# ==== merged from crackproof_encrypt_primitives.py
# ======================================================================





def w16(b, o, v): struct.pack_into('<H', b, o, v & 0xFFFF)
def w32(b, o, v): struct.pack_into('<I', b, o, v & 0xFFFFFFFF)
def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]


# ---------------------------------------------------------------- Data1
def encrypt_data1_info(info):
    """Inverse of decrypt_data1. Returns 32 bytes (8 encrypted dwords) to be
    written at file offset 0x1000. Requires info[1]==0x4E4E4F4B (KONN)."""
    out = bytearray(32)
    tmp = info[0] & M
    w32(out, 0, tmp)
    for i in range(7):
        val = (tmp ^ info[i + 1]) & M
        w32(out, (i + 1) * 4, val)
        tmp = ((i * i) ^ ((tmp + val) & M) - i) & M
    return bytes(out)


# ---------------------------------------------------------------- Data2
def encrypt_data2_shell(plain, info, decrypt_size):
    """Inverse of decrypt_data2. `plain` is the decrypted shell bytes for image
    region [info[3] : info[3]+decrypt_size]. Returns the encrypted dword stream
    to write at file offset info[4]+0x1000. len(plain) must be a multiple of 4
    and >= decrypt_size; only the first decrypt_size bytes are transformed."""
    count = decrypt_size >> 2
    out = bytearray(count * 4)
    tmp = (info[0] + (~decrypt_size & M)) & M
    for i in range(count):
        p = u32(plain, i * 4)
        enc = (tmp ^ p) & M
        w32(out, i * 4, enc)
        tmp = ((i * i) ^ ((tmp + enc + i) & M)) & M
    return bytes(out)


# ---------------------------------------------------------------- Data3
def encrypt_data3_dwords(buf, off, key, dword_count, shift):
    """In-place inverse of decrypt_data3 over `dword_count` dwords at `off`.
    decrypt:  v = enc^key; key+=i; v = ror(v,shift); v -= i
    encrypt:  v = (plain+i); v = rol(v,shift); enc = v^key; key += i"""
    for i in range(dword_count):
        plain = u32(buf, off + i * 4)
        v = (plain + i) & M
        v = ((v << shift) | (v >> (32 - shift))) & M
        enc = v ^ key
        w32(buf, off + i * 4, enc)
        key = (key + i) & M


# ---------------------------------------------------------------- Data4
_d4_inv = None


def _build_d4_inv():
    global _d4_inv
    if _d4_inv is not None:
        return
    d._build_d4_lut()
    _d4_inv = [[None] * 256 for _ in range(256)]
    for k1 in range(256):
        for k2 in range(256):
            fwd = d._d4_lut[k1][k2]
            inv = bytearray(256)
            for enc, dec in enumerate(fwd):
                inv[dec] = enc
            _d4_inv[k1][k2] = inv


def encrypt_data4(buf, data_offset):
    """In-place inverse of decrypt_data4 over an 8-byte record (size read like
    the decryptor: va=u32(off), sz=u32(off+4)). Mirrors the key schedule."""
    _build_d4_inv()
    va = u32(buf, data_offset)
    sz = u32(buf, data_offset + 4)
    key1 = ((va >> 8) + va) & 0xFF
    key2 = (key1 + 1) & 0xFF
    for i in range(sz):
        buf[va + i] = _d4_inv[key1][key2][buf[va + i]]
        key1 = (key1 + 1) & 0xFF
        key2 = (key2 + 1) & 0xFF


def encrypt_data4_at(buf, abs_off, length, region_va):
    """Inverse of decrypt_data4 applied to a SUB-RANGE [abs_off:abs_off+length]
    of a larger Data4 region whose base address is `region_va`. decrypt_data4 is
    a per-byte LUT cipher whose key advances one step per byte from
    key1=((region_va>>8)+region_va)&0xff at region_va; this re-encrypts a slice
    in the middle by fast-forwarding the key to the slice's offset. No inter-byte
    chaining, so only the touched bytes change."""
    _build_d4_inv()
    start = ((region_va >> 8) + region_va) & 0xFF
    off = abs_off - region_va
    key1 = (start + off) & 0xFF
    key2 = (key1 + 1) & 0xFF
    for i in range(length):
        buf[abs_off + i] = _d4_inv[key1][key2][buf[abs_off + i]]
        key1 = (key1 + 1) & 0xFF
        key2 = (key2 + 1) & 0xFF


# ---------------------------------------------------------------- Data5
_d5_inv = None


def _build_d5_inv():
    global _d5_inv
    if _d5_inv is not None:
        return
    d._build_d5_lut()
    _d5_inv = [[None] * 256 for _ in range(256)]
    for k1 in range(256):
        for k2 in range(256):
            fwd = d._d5_lut[k1][k2]
            inv = bytearray(256)
            for enc, dec in enumerate(fwd):
                inv[dec] = enc
            _d5_inv[k1][k2] = inv


def encrypt_data5(buf, va, size):
    """In-place inverse of decrypt_data5. key1=va&0xff, key2=key1+1."""
    _build_d5_inv()
    key1 = va & 0xFF
    key2 = (key1 + 1) & 0xFF
    for i in range(size):
        buf[va + i] = _d5_inv[key1][key2][buf[va + i]]
        key1 = (key1 + 1) & 0xFF
        key2 = (key2 + 1) & 0xFF


def encrypt_data5_record(record_bytes, va):
    """Encrypt a standalone 16-byte (or N-byte) record as if it lived at image
    address `va`. Returns encrypted bytes. Pure helper for table building."""
    buf = bytearray(record_bytes)
    # Use a temporary buffer indexed from 0 but with the key schedule of `va`.
    _build_d5_inv()
    key1 = va & 0xFF
    key2 = (key1 + 1) & 0xFF
    for i in range(len(buf)):
        buf[i] = _d5_inv[key1][key2][buf[i]]
        key1 = (key1 + 1) & 0xFF
        key2 = (key2 + 1) & 0xFF
    return bytes(buf)


# ---------------------------------------------------------------- Data6 (symmetric)
def data6_xor(buf, data_offset):
    """Symmetric LFSR transform; encrypt == decrypt == decrypt_data6."""
    d.decrypt_data6(buf, data_offset)


# ---------------------------------------------------------------- Data7
def encrypt_data7(buf, off, key):
    """Inverse of decrypt_data7 (import name obfuscation).
    decrypt: b=swap_nibbles(enc); b-=key; if b==0: b=(-key)&0xff; key+=67
    Forward map over a plaintext null-terminated string at `off`:
      x = (plain + key) & 0xff
      enc = swap_nibbles(key) if x == 0 else swap_nibbles(x)
      key = (key + 67) & 0xff

    CrackProof's contract is that a name's ciphertext NEVER contains a 0x00 byte
    (decrypt_data7 stops at the first 0). The naive enc=swap(x) injects 0x00
    whenever (plain + key) & 0xff == 0 (i.e. plain == (-key)&0xff), which
    truncates the DLL/function name when it is later unpacked (e.g. iphlpapi.dll
    -> "iphl", gdi32.dll -> "gdi"). We mirror the decryptor's `if b==0` branch:
    emit enc=swap(key) for that character, which decrypts back to plain via the
    special case and is always non-zero here (this branch implies key!=0, since
    plain!=0 in a null-terminated string). swap() is a bijection, so x!=0 implies
    enc!=0 too -> the whole ciphertext is guaranteed 0x00-free."""
    idx = 0
    while buf[off + idx] != 0:
        plain = buf[off + idx]
        x = (plain + key) & 0xFF
        if x == 0:
            enc = ((key << 4) | (key >> 4)) & 0xFF   # swap(key); decrypt special case restores plain
        else:
            enc = ((x << 4) | (x >> 4)) & 0xFF
        buf[off + idx] = enc
        key = (key + 67) & 0xFF
        idx += 1


# ---------------------------------------------------------------- Data8 (symmetric)
def apply_data8_page(buf, page_off, key):
    """Symmetric per-page .text transform; encrypt == decrypt.
    Mirrors decrypt_crackproof _apply_d8_page exactly."""
    k = key & M
    k = ((k >> 15) | (k << 17)) & M
    for bi in range(1, 256):
        rk = ((k >> 15) | (k << 17)) & M
        ri = (rk + bi) & M
        k = (ri + bi) & M
        tidx = page_off + bi * 16 + (ri & 0xF)
        buf[tidx] = (buf[tidx] ^ k) & 0xFF


# ---------------------------------------------------------------- AES-CBC encrypt
# Forward AES S-box, built lazily from the loaded inverse S-box. Building it at
# import time would fail because decrypt_crackproof loads its tables only when
# load_aes_tables() is called by the caller.
_SBOX = None


def _ensure_sbox():
    global _SBOX
    if _SBOX is not None:
        return
    if d._sbox is None:
        raise RuntimeError(
            'AES tables not loaded; call decrypt_crackproof.load_aes_tables(dir) first')
    inv = [w & 0xFF for w in d._sbox]
    sbox = [0] * 256
    for i, v in enumerate(inv):
        sbox[v] = i
    _SBOX = sbox


def _xtime(v):
    return (((v << 1) ^ 0x1B) & 0xFF) if v & 0x80 else ((v << 1) & 0xFF)


def _mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = _xtime(a)
        b >>= 1
    return out


def _mix_col(c):
    return [
        _mul(c[0], 2) ^ _mul(c[1], 3) ^ c[2] ^ c[3],
        c[0] ^ _mul(c[1], 2) ^ _mul(c[2], 3) ^ c[3],
        c[0] ^ c[1] ^ _mul(c[2], 2) ^ _mul(c[3], 3),
        _mul(c[0], 3) ^ c[1] ^ c[2] ^ _mul(c[3], 2),
    ]


def _mix_word(word):
    m = _mix_col([(word >> 24) & 255, (word >> 16) & 255, (word >> 8) & 255, word & 255])
    return (m[0] << 24) | (m[1] << 16) | (m[2] << 8) | m[3]


def _add_round_key(state, words):
    key = []
    for word in words:
        key.extend([(word >> 24) & 255, (word >> 16) & 255, (word >> 8) & 255, word & 255])
    return [v ^ key[i] for i, v in enumerate(state)]


def _sub_bytes(state):
    return [_SBOX[v] for v in state]


def _shift_rows(s):
    return [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]


def _mix_columns(s):
    out = s[:]
    for col in range(4):
        o = col * 4
        out[o:o + 4] = _mix_col(s[o:o + 4])
    return out


def _read_decrypt_round_keys(buf, key_off):
    rounds = u16(buf, key_off + 2)
    base = key_off + 4
    return [[u32(buf, base + r * 16 + w * 4) for w in range(4)] for r in range(rounds + 1)]


def _derive_encrypt_keys(decrypt_keys):
    rounds = len(decrypt_keys) - 1
    ek = [None] * (rounds + 1)
    ek[0] = decrypt_keys[rounds]
    ek[rounds] = decrypt_keys[0]
    for r in range(1, rounds):
        ek[r] = [_mix_word(w) for w in decrypt_keys[rounds - r]]
    return ek


def _aes_encrypt_block(block, ek):
    rounds = len(ek) - 1
    state = _add_round_key(list(block), ek[0])
    for r in range(1, rounds):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, ek[r])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, ek[rounds])
    return bytes(state)


def aes_encrypt_cbc(buf, data_off, size, key_off):
    """Inverse of decrypt_crackproof.aes_decrypt. CBC, IV=0, key schedule is the
    stored decrypt schedule at key_off (reversed to a forward schedule). The key
    schedule and the data live in the SAME buffer (like the decryptor)."""
    _ensure_sbox()
    ek = _derive_encrypt_keys(_read_decrypt_round_keys(buf, key_off))
    prev = bytes(16)
    for bi in range(size >> 4):
        off = data_off + bi * 16
        plain = bytes(buf[off:off + 16])
        mixed = bytes(v ^ prev[i] for i, v in enumerate(plain))
        cipher = _aes_encrypt_block(mixed, ek)
        buf[off:off + 16] = cipher
        prev = cipher


def derive_aes_encrypt_keys(key_buf, key_off):
    """Derive the forward AES round keys from the stored decrypt schedule at
    key_off in key_buf. Use with aes_encrypt_cbc_ek when the key schedule and
    the data live in DIFFERENT buffers (e.g. encoding standalone file blocks
    whose AES schedule lives in the image)."""
    _ensure_sbox()
    return _derive_encrypt_keys(_read_decrypt_round_keys(key_buf, key_off))


def aes_encrypt_cbc_ek(buf, data_off, size, ek):
    """AES-CBC encrypt (IV=0) using pre-derived forward round keys `ek`. Only
    full 16-byte blocks are transformed; any tail bytes are left untouched,
    matching decrypt_crackproof.aes_decrypt (nblocks = size >> 4)."""
    prev = bytes(16)
    for bi in range(size >> 4):
        off = data_off + bi * 16
        plain = bytes(buf[off:off + 16])
        mixed = bytes(v ^ prev[i] for i, v in enumerate(plain))
        cipher = _aes_encrypt_block(mixed, ek)
        buf[off:off + 16] = cipher
        prev = cipher


# ---------------------------------------------------------------- customDecryptor inverse
def inverse_translate_table(custom_dec):
    """custom_dec = (lut, translate) from generate_custom_decryptor, where lut
    maps cipher->plain. Returns a bytes.maketrans table for plain->cipher."""
    lut, _ = custom_dec
    inv = bytearray(256)
    for cipher, plain in enumerate(lut):
        inv[plain] = cipher
    return bytes.maketrans(bytes(range(256)), bytes(inv))


# ======================================================================
# ==== merged from crackproof_repack.py
# ======================================================================



d = e.d  # the decrypt_crackproof module (shared singleton)



def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]


def load_tables(aes_dir=DEFAULT_AES_DIR):
    d.load_aes_tables(str(aes_dir) if aes_dir else None)


def decrypt_shell_plaintext(file_data):
    """Return (info, image_buffer, decrypt_size). image_buffer has the Data2
    shell region [info3:info3+decrypt_size] decrypted and the raw tail copied.

    IMPORTANT: unlike decrypt_crackproof.main() Stage 2, we do NOT apply the
    unpacker's post-fixups (w32(info[3], 0x1000) and the PE-header copy into
    image[:0x1000]). Those mutate the decrypted shell plaintext; for faithful
    re-emission we must keep the raw decrypt_data2 output so encrypt_data2 round
    trips exactly. (The real first shell dword at info[3] is 0x00000000.)"""
    info = d.decrypt_data1(file_data)
    if info[1] != 0x4E4E4F4B:
        raise ValueError('not a CrackProof sample (bad KONN magic)')
    pe = u32(file_data, 0x3C)
    image_size = u32(file_data, pe + 80)
    decrypt_size = info[6] - info[3] + 0x2000
    data = bytearray(image_size)
    d.decrypt_data2(file_data, data, info, decrypt_size)
    src_off = info[4] + 0x1000 + decrypt_size
    dst_off = info[3] + decrypt_size
    remain = info[5] - decrypt_size
    data[dst_off:dst_off + remain] = file_data[src_off:src_off + remain]
    return info, data, decrypt_size


def reemit_outer_identity(file_data):
    """Re-encode info[] and the Data2 shell from the decrypted plaintext, leaving
    every other byte (PE header, header seeds, raw tail, payload) as-is. If the
    encoder primitives are exact inverses, the result is byte-identical to the
    input packed file."""
    info, image, decrypt_size = decrypt_shell_plaintext(file_data)
    plain_shell = bytes(image[info[3]:info[3] + decrypt_size])

    enc_info = e.encrypt_data1_info(info)
    enc_shell = e.encrypt_data2_shell(plain_shell, info, decrypt_size)

    out = bytearray(file_data)
    out[0x1000:0x1000 + 32] = enc_info
    shell_src = info[4] + 0x1000
    out[shell_src:shell_src + len(enc_shell)] = enc_shell
    return bytes(out)


class TemplateProfile:
    """Everything the repacker needs about a PE32+ template, captured by fully
    unpacking it once. Addresses are image RVAs unless noted."""

    def __init__(self):
        self.info = None
        self.pe = 0
        self.image_size = 0
        self.decrypt_size = 0
        self.compress_data_offset = 0
        self.raw_shell = None       # decrypt_data2 output (+raw tail), NO fixups
        self.decoded_image = None   # working image right after the file loop
        self.key_offsets = None
        self.eighth_start = 0
        self.file_dec = None        # generate_custom_decryptor() for the file LFSR
        self.compressed_info_addr = 0   # image addr where compressedInfo records live
        self.compressed_records = None  # list of (src, s_size, dst, d_size)
        self.file_cs_addr = 0
        self.data4_va = 0           # infoTable slot0 Data4 region base (outer layer)
        self.data4_sz = 0           # infoTable slot0 Data4 region size
        self.meta_off = 0           # metadata block image addr (Data4-removed,Data5-enc)
        self.meta_size = 0          # metadata block size
        self.meta_ep_rel = 0        # EP field offset within the metadata block
        self.meta_plain = None      # decrypted metadata block bytes
        self.meta_ep = 0            # original entry point (RVA)


# Pin the pickled class path to the stable 'crackproof_repack' name (aliased to
# this module above) so extracted stub profiles load regardless of whether the
# tool runs as __main__ or is imported. Without this, profiles extracted while
# running as a script would pickle under '__main__' and fail to load elsewhere.
TemplateProfile.__module__ = 'crackproof_repack'


DEBUG_STAGES = False


def _stage_dbg(data, pair_addr, name, info3):
    if not DEBUG_STAGES:
        return
    src = u32(data, pair_addr)
    s = u32(data, pair_addr + 4)
    dst = u32(data, pair_addr + 8)
    dd = u32(data, pair_addr + 12)
    covers = dst <= info3 < dst + dd or dst <= info3 + 0x280 < dst + dd
    flag = '  <== writes info[3] region!' if covers else ''
    print(f'  [stage {name}] src=0x{src:X} s=0x{s:X} dst=0x{dst:X} d=0x{dd:X}'
          f' (range 0x{dst:X}..0x{dst + dd:X}){flag}')


def _capture_metadata(data, info3, image_size):
    """Capture the metadata block (EP + data dirs) from the post-stage-walk
    image (Data4 already removed by infoTable slot0, still Data5-encrypted).
    Returns (meta_off, meta_size, ep_rel, plaintext, ep) for the chosen layout,
    mirroring the decryptor's layout pick (prefer B, fall back to A). Restores
    `data`. Returns None if neither layout yields an in-image EP."""
    cand_b = None
    cand_a = None
    for off, size, ep_rel, into in (
            (info3 + 0x10, 0x290, 0x10, 'B'), (info3 + 0x40, 144, 0x00, 'A')):
        backup = bytes(data[off:off + size])
        d.decrypt_data5(data, off, size)
        ep = u32(data, off + ep_rel)
        plain = bytes(data[off:off + size])
        data[off:off + size] = backup
        rec = (off, size, ep_rel, plain, ep)
        if into == 'B':
            cand_b = rec
        else:
            cand_a = rec
    if cand_b and 0 <= cand_b[4] < image_size:
        return cand_b
    if cand_a and 0 < cand_a[4] < image_size:
        return cand_a
    return cand_b or cand_a


def unpack_template(file_data):
    """Dispatch to the PE32 or PE32+ template parser by optional-header magic."""
    pe = u32(file_data, 0x3C)
    if u16(file_data, pe + 24) == 0x10B:
        return unpack_template_pe32(file_data)
    return unpack_template_pe32p(file_data)


def unpack_template_pe32p(file_data):
    """Fully unpack a PE32+ CrackProof sample and capture a TemplateProfile.
    Mirrors decrypt_crackproof.main() PE32+ path through the file-decode loop."""
    info = d.decrypt_data1(file_data)
    if info[1] != 0x4E4E4F4B:
        raise ValueError('not a CrackProof sample (bad KONN magic)')
    pe = u32(file_data, 0x3C)
    image_size = u32(file_data, pe + 80)
    decrypt_size = info[6] - info[3] + 0x2000

    # raw_shell: decrypt_data2 output + raw tail, NO unpacker fixups (for outer
    # + table/metadata re-emission, where the tables are still Data5-encrypted).
    raw_shell = bytearray(image_size)
    d.decrypt_data2(file_data, raw_shell, info, decrypt_size)
    src_off = info[4] + 0x1000 + decrypt_size
    dst_off = info[3] + decrypt_size
    remain = info[5] - decrypt_size
    raw_shell[dst_off:dst_off + remain] = file_data[src_off:src_off + remain]

    # working buffer for the live stage walk (with the unpacker fixups).
    data = bytearray(raw_shell)
    d.w32(data, info[3], 0x1000)
    data[:0x1000] = file_data[:0x1000]

    def _probe(label):
        if DEBUG_STAGES:
            print(f'  [probe @0x9FE280 after {label}] {bytes(data[0x9FE280:0x9FE290]).hex()}')
    _probe('raw Data2')

    # ---- locate anchor/fcs ----
    shell = info[6]
    anchor = fcs = None
    for off in range(shell, min(shell + 0x3000, len(data) - 0x100), 4):
        if u32(data, off) == info[3]:
            for delta in range(0x20, 0x60, 4):
                if off + delta < len(data) and u32(data, off + delta) == info[6]:
                    anchor, fcs = off, off + delta
                    break
            if anchor is not None:
                break
    if anchor is None:
        raise ValueError('cannot locate shell anchor')

    # PE header restore (covered by header checksum) — needed for correct keys.
    d.w32(data, pe + 144, u32(data, anchor + 0x08))
    d.w32(data, pe + 148, u32(data, anchor + 0x04))
    d.w32(data, pe + 152, u32(data, fcs - 0x10))
    d.w32(data, pe + 156, u32(data, fcs - 0x0C))
    d.w32(data, pe + 176, 0)
    d.w32(data, pe + 180, 0)

    header_checksum = 0
    hcs = fcs + 0x80
    while u32(data, hcs + 4) != 0:
        header_checksum ^= d.checksum_with_size_xor(data, hcs)
        hcs += 8
    first_stage_cs = d.checksum_with_size_xor(data, fcs)
    second_stage_key = u32(data, anchor + 0x14)
    ss_key = (header_checksum ^ first_stage_cs ^ second_stage_key) & 0xFFFFFFFF
    d.decrypt_data3(data, fcs + 0x40, ss_key, 21)
    ss = u32(data, fcs + 0x40)
    ss_size = u32(data, fcs + 0x40 + 4)

    pair_shift = ss_size - 0x10C8
    kernel32_off = None
    for koff in range(0xD80, min(ss_size - 16, 0xF00)):
        if data[ss + koff:ss + koff + 13] == b'Kernel32.dll\x00':
            kernel32_off = koff
            break
    if kernel32_off is not None:
        third_key_off = kernel32_off - 0x34
        forth_key_off = kernel32_off - 0x30
        seven_cs_off = kernel32_off - 0x18
        fifth_cs_off = kernel32_off - 0x10
        forth_cs_off = kernel32_off - 0x08
    else:
        third_key_off = 0x0D74 + pair_shift
        forth_key_off = 0x0D78 + pair_shift
        seven_cs_off = 0x0D90 + pair_shift
        fifth_cs_off = 0x0D98 + pair_shift
        forth_cs_off = 0x0DA0 + pair_shift
    third_pair_off = 0x0E30 + pair_shift
    forth_pair_off = 0x0E88 + pair_shift
    fifth_pair_off = 0x0E98 + pair_shift
    seven_pair_off = 0x0EB8 + pair_shift
    eighth_pair_off = 0x0F08 + pair_shift

    third_key = u32(data, ss + third_key_off)
    forth_key_base = u32(data, ss + forth_key_off)
    d.decrypt_data3(data, ss + third_pair_off, third_key, 19)
    ts = u32(data, ss + third_pair_off)
    ts_size = u32(data, ss + third_pair_off + 4)

    info_table = keys_addr = None
    for off in range(0, ts_size - 32, 4):
        if u32(data, ts + off) in (1, 0x11) and u32(data, ts + off + 16) == 2:
            addr0 = u32(data, ts + off + 4)
            if 0x1000 < addr0 < len(data):
                info_table = ts + off
                keys_addr = info_table - 0x58
                break
    if info_table is None:
        raise ValueError('cannot locate infoTable')
    # Capture the Data4 region from slot0 (outer layer over the control tables:
    # metadata, compressedInfo, fileCS ...). va/sz are plaintext pointers that
    # decrypt_data4 reads but does not mutate.
    data4_va = u32(data, info_table + 4)
    data4_sz = u32(data, info_table + 8)
    if DEBUG_STAGES:
        print(f'  [Data4 region] va=0x{data4_va:X} sz=0x{data4_sz:X}'
              f' (range 0x{data4_va:X}..0x{data4_va + data4_sz:X})')
    it = info_table
    for _ in range(2):
        tval = u32(data, it)
        if tval in (1, 0x11):
            d.decrypt_data4(data, it + 4)
        elif tval == 2:
            ca = u32(data, it + 4)
            while True:
                d.decrypt_data5(data, ca, 16)
                s_a, s_sz = u32(data, ca), u32(data, ca + 4)
                d_a, d_sz = u32(data, ca + 8), u32(data, ca + 12)
                ca += 16
                if s_sz == 0:
                    break
                if s_a and d_a and d_sz == s_sz:
                    data[d_a:d_a + s_sz] = data[s_a:s_a + s_sz]
        it += 16
    key_offsets = [0] * 4
    ka = keys_addr
    for k in range(2):
        ka2 = ka
        for l in range(2):
            d.decrypt_data4(data, ka2)
            key_offsets[k * 2 + l] = u32(data, ka2)
            ka2 += 8
        ka += 32
    _probe('infoTable/keyOffsets')

    # Forth
    second_stage_cs = d.checksum_with_size_xor(data, fcs - 0x08)
    forth_key = d.advance_key(forth_key_base, 4)
    fk4 = (header_checksum ^ second_stage_cs ^ forth_key) & 0xFFFFFFFF
    _stage_dbg(data, ss + forth_pair_off, 'Forth', info[3])
    d.decrypt_and_decompress(data, ss + forth_pair_off, fk4, key_offsets)
    _probe('Forth')
    # Fifth
    forth_cs = d.checksum_with_size_xor(data, ss + forth_cs_off)
    fro = u32(data, ss + forth_cs_off)
    frs = u32(data, ss + forth_cs_off + 4)
    fifth_key = u32(data, fro + frs - 4)
    fk5 = (header_checksum ^ forth_cs ^ fifth_key) & 0xFFFFFFFF
    _stage_dbg(data, ss + fifth_pair_off, 'Fifth', info[3])
    d.decrypt_and_decompress(data, ss + fifth_pair_off, fk5, key_offsets)
    _probe('Fifth')
    fifth_addr = ss + fifth_pair_off
    fifth_start = u32(data, fifth_addr)
    fifth_dsz = u32(data, fifth_addr + 12)
    # Seven
    fifth_cs = d.checksum_with_size_xor(data, ss + fifth_cs_off)
    seven_addr = ss + seven_pair_off
    seven_src = u32(data, seven_addr)
    seven_ssz = u32(data, seven_addr + 4)
    sb = bytearray(data[seven_src:seven_src + seven_ssz])
    spb = bytearray(data[seven_addr:seven_addr + 16])
    cand = [c for c in [0x7B0, 0x7A8, 0x7A0, 0x798, 0x880, 0x878, 0x870, 0x868,
                        0x860, 0x858, 0x830] if c + 4 <= fifth_dsz]
    for sk in range(max(0, fifth_dsz // 2), fifth_dsz - 4, 4):
        if sk not in cand and u32(data, fifth_start + sk) not in (0, 0xCCCCCCCC):
            cand.append(sk)
    ok = False
    for sk in cand:
        data[seven_src:seven_src + seven_ssz] = sb
        data[seven_addr:seven_addr + 16] = spb
        fk7 = (header_checksum ^ fifth_cs ^ ((~u32(data, fifth_start + sk)) & 0xFFFFFFFF)) & 0xFFFFFFFF
        try:
            if d.decrypt_and_decompress(data, seven_addr, fk7, key_offsets, verbose=False) \
                    and 0x1000 < u32(data, seven_addr) < len(data):
                ok = True
                break
        except Exception:
            pass
    if not ok:
        raise ValueError('cannot decrypt sevenStage')
    seven_start = u32(data, seven_addr)
    seven_dsz = u32(data, seven_addr + 12)
    _stage_dbg(data, seven_addr, 'Seven', info[3])
    cdo_off = d.find_lfsr_block(data, seven_start, seven_dsz, max(0, seven_dsz // 2), scan_backward=True)
    if cdo_off is None:
        cdo_off = d.find_lfsr_block(data, seven_start, seven_dsz, 0)
    d.decrypt_data6(data, seven_start + cdo_off)
    stage_custom_dec = d.generate_custom_decryptor(data, seven_start + cdo_off)
    # Eighth
    seven_cs = d.checksum_with_size_xor(data, ss + seven_cs_off)
    eighth_addr = ss + eighth_pair_off
    eighth_src = u32(data, eighth_addr)
    eighth_ssz = u32(data, eighth_addr + 4)
    eb = bytearray(data[eighth_src:eighth_src + eighth_ssz])
    epb = bytearray(data[eighth_addr:eighth_addr + 16])
    ekc = []
    for gap in [0x28, 0x50, 0x48, 0x30, 0x40, 0x58, 0x60, 0x20, 0x38]:
        o = cdo_off - gap
        if 0 <= o and o + 4 <= seven_dsz and u32(data, seven_start + o) not in (0, 0xCCCCCCCC):
            ekc.append(o)
    for o in range(max(0, cdo_off - 0x100), cdo_off, 4):
        if o not in ekc:
            v = u32(data, seven_start + o)
            if v not in (0, 0xCCCCCCCC) and not all(32 <= ((v >> (i * 8)) & 0xFF) < 127 for i in range(4)):
                ekc.append(o)
    ok = False
    for o in ekc:
        data[eighth_src:eighth_src + eighth_ssz] = eb
        data[eighth_addr:eighth_addr + 16] = epb
        fk8 = (header_checksum ^ fifth_cs ^ seven_cs ^ d.advance_key(u32(data, seven_start + o), 3)) & 0xFFFFFFFF
        try:
            if d.decrypt_and_decompress(data, eighth_addr, fk8, key_offsets, stage_custom_dec, verbose=False) \
                    and 0x1000 < u32(data, eighth_addr) < len(data):
                ok = True
                break
        except Exception:
            pass
    if not ok:
        raise ValueError('cannot decrypt eighthStage')
    eighth_start = u32(data, eighth_addr)
    eighth_dsz = u32(data, eighth_addr + 12)
    _stage_dbg(data, eighth_addr, 'Eighth', info[3])
    _probe('Eighth')

    # ---- locate file tables (file LFSR + compressedInfo) ----
    compress_data_offset = ((~u32(file_data, 0x1080)) & 0xFFFFFFFF) + 0x1000
    all_lfsrs = []
    so = 0
    while so < eighth_dsz - 95:
        f = d.find_lfsr_block(data, eighth_start, eighth_dsz, start_off=so)
        if f is None:
            break
        all_lfsrs.append(f)
        so = f + 96
    off_file_lfsr = None
    best = None
    for lo in all_lfsrs:
        co = lo - 0x58
        if co < 0:
            continue
        cv = u32(data, eighth_start + co)
        if not (0x1000 < cv < len(data)) or cv < info[3]:
            continue
        dd = cv - info[3]
        if best is None or dd < best:
            best, off_file_lfsr = dd, lo
    if off_file_lfsr is None:
        for lo in reversed(all_lfsrs):
            co = lo - 0x58
            if co >= 0 and 0x1000 < u32(data, eighth_start + co) < len(data):
                off_file_lfsr = lo
                break
    if off_file_lfsr is None:
        raise ValueError('cannot locate file LFSR')
    off_file_cs = off_file_lfsr - 0x58
    file_cs_addr = u32(data, eighth_start + off_file_cs)

    anchor_off = None
    for ao in range(eighth_dsz - 8, 0, -1):
        if data[eighth_start + ao:eighth_start + ao + 8] == b'pm\x00\x00cm\x00\x00':
            anchor_off = ao
            break
    scan_from = anchor_off if anchor_off is not None else max(off_file_lfsr - 0x400, 0)
    _ci_cands = []
    for doff in range(scan_from, off_file_lfsr, 4):
        v = u32(data, eighth_start + doff)
        if doff == off_file_cs or not (0x1000 < v < len(data) - 16):
            continue
        bk = bytes(data[v:v + 16])
        d.decrypt_data5(data, v, 16)
        s2, ss2, d2, ds2 = u32(data, v), u32(data, v + 4), u32(data, v + 8), u32(data, v + 12)
        data[v:v + 16] = bk
        if (0 < ss2 < 0x200000 and s2 + compress_data_offset + ss2 <= len(file_data)
                and d2 >= 0x1000 and d2 + ds2 <= len(data) and ds2 >= ss2 and ds2 < 0x200000):
            _ci_cands.append((doff, v))
    # Prefer the candidate whose table pointer sits closest to (>=) info[3]; the real
    # compressedInfo lives just past the metadata (info3+~0x280), decoys sit higher.
    off_compressed_info = None
    if _ci_cands:
        info3v = info[3]
        off_compressed_info = sorted(
            _ci_cands, key=lambda c: (c[1] - info3v) if c[1] >= info3v else (1 << 62))[0][0]
    if off_compressed_info is None:
        raise ValueError('cannot locate compressedInfo')
    compressed_info_addr = u32(data, eighth_start + off_compressed_info)

    # ---- file checksum decrypt (mirror decryptor) ----
    fc = file_cs_addr
    while u32(data, fc + 4) != 0:
        d.decrypt_data5(data, fc, 16)
        fc += 16

    # ---- file decryptor (file LFSR) ----
    file_dec_addr = eighth_start + off_file_lfsr
    d.decrypt_data6(data, file_dec_addr)
    file_dec = d.generate_custom_decryptor(data, file_dec_addr)
    if file_dec is None:
        raise ValueError('cannot generate file decryptor')

    # ---- file-decode loop: capture records + decoded image ----
    # OVERLAP packs decompress the program tail over [info3:image], clobbering the
    # compressedInfo table + key tables (AES schedule key_offsets[2], LZ huffman
    # key_offsets[0]) that live there. Cache the key tables and read ALL records
    # before decompressing (mirrors the runtime, which loads them once).
    compressed_records = []
    ci = compressed_info_addr
    _probe('before file loop')
    meta = _capture_metadata(data, info[3], image_size)
    # Phase 1: read ALL records while the compressedInfo table is still intact
    # (OVERLAP decompression below clobbers it).
    while True:
        d.decrypt_data5(data, ci, 16)
        s2, ss2 = u32(data, ci), u32(data, ci + 4)
        d2, ds2 = u32(data, ci + 8), u32(data, ci + 12)
        ci += 16
        if ss2 == 0:
            break
        compressed_records.append((s2, ss2, d2, ds2))
    # Grow the buffer so every record destination (and the target SizeOfImage) is
    # in-bounds. A large OVERLAP target's image exceeds the packed-file-derived
    # buffer and would otherwise overflow at d2 inside aes_decrypt (struct.error)
    # and clobber the scratch key cache, which must live ABOVE the image.
    need = len(data)
    for _s2, _ss2, _d2, _ds2 in compressed_records:
        need = max(need, _d2 + _ss2, _d2 + _ds2)
    need = max(need, image_size)
    if len(data) < need:
        data.extend(b'\x00' * (need - len(data)))
    # Scratch ABOVE the image: cache the key tables the decompression clobbers.
    _scr = len(data)
    data.extend(b'\x00' * 0x4000)
    _ko2 = _scr
    data[_ko2:_ko2 + 0x1000] = data[key_offsets[2]:key_offsets[2] + 0x1000]
    _ko0 = _scr + 0x2000
    data[_ko0:_ko0 + 0x1000] = data[key_offsets[0]:key_offsets[0] + 0x1000]
    # Phase 2: decompress (clobbers the table region; records already captured).
    for s2, ss2, d2, ds2 in compressed_records:
        fsrc = s2 + compress_data_offset
        chunk = file_data[fsrc:fsrc + ss2]
        if len(chunk) < ss2:                 # source truncated -> zero-fill tail
            chunk = chunk + b'\x00' * (ss2 - len(chunk))
        data[d2:d2 + ss2] = chunk
        d.aes_decrypt(data, d2, ss2, _ko2)
        _lut, tt = file_dec
        data[d2:d2 + ss2] = bytearray(bytes(data[d2:d2 + ss2]).translate(tt))
        if ss2 != ds2:
            d.decompress(data, d2, d2, _ko0, ss2, ds2)
    del data[_scr:]
    decoded_image = bytearray(data)  # snapshot before zeroList

    prof = TemplateProfile()
    prof.info = info
    prof.pe = pe
    prof.image_size = image_size
    prof.decrypt_size = decrypt_size
    prof.compress_data_offset = compress_data_offset
    prof.raw_shell = raw_shell
    prof.decoded_image = decoded_image
    prof.key_offsets = key_offsets
    prof.eighth_start = eighth_start
    prof.file_dec = file_dec
    prof.compressed_info_addr = compressed_info_addr
    prof.compressed_records = compressed_records
    prof.file_cs_addr = file_cs_addr
    prof.data4_va = data4_va
    prof.data4_sz = data4_sz
    if meta is not None:
        prof.meta_off, prof.meta_size, prof.meta_ep_rel, prof.meta_plain, prof.meta_ep = meta
    return prof


def unpack_template_pe32(file_data):
    """Fully unpack a PE32 (32-bit) CrackProof sample and capture a
    TemplateProfile. Mirrors decrypt_crackproof.main() PE32 path through the
    file-decode loop (find_tbl, fixed offsets, in-place ThirdStage, fixed table
    offsets, zeroList-before-loop)."""
    info = d.decrypt_data1(file_data)
    if info[1] != 0x4E4E4F4B:
        raise ValueError('not a CrackProof sample (bad KONN magic)')
    pe = u32(file_data, 0x3C)
    image_size = u32(file_data, pe + 80)
    decrypt_size = info[6] - info[3] + 0x2000

    raw_shell = bytearray(image_size)
    d.decrypt_data2(file_data, raw_shell, info, decrypt_size)
    src_off = info[4] + 0x1000 + decrypt_size
    dst_off = info[3] + decrypt_size
    remain = info[5] - decrypt_size
    raw_shell[dst_off:dst_off + remain] = file_data[src_off:src_off + remain]

    data = bytearray(raw_shell)
    d.w32(data, info[3], 0x1000)
    data[:0x1000] = file_data[:0x1000]

    tbl = d.find_tbl(data, info)
    if tbl is None:
        raise ValueError('cannot locate tbl in shell (PE32)')

    # PE header restore (covered by header checksum).
    d.w32(data, pe + 0x80, u32(data, tbl + 0xBC))
    d.w32(data, pe + 0x88, u32(data, tbl + 0xC8))
    d.w32(data, pe + 0x8C, u32(data, tbl + 0xCC))
    d.w32(data, pe + 0xB0, 0)
    d.w32(data, pe + 0xB4, 0)

    header_checksum = 0
    hcs = tbl + 0x58
    while u32(data, hcs + 4) != 0:
        pa = u32(data, hcs); ps = u32(data, hcs + 4)
        header_checksum ^= (d.crc32(data, pa, ps) ^ ps)
        hcs += 8
    first_stage_cs = d.checksum_with_size_xor(data, tbl + 0xA8)
    second_stage_key = u32(data, tbl + 0x40)
    ss_pair = tbl + 0x98
    ss_key = (header_checksum ^ first_stage_cs ^ second_stage_key) & 0xFFFFFFFF
    d.decrypt_data3(data, ss_pair, ss_key, 21)
    ss = u32(data, ss_pair)
    ss_size = u32(data, ss_pair + 4)
    ss_shift = ss_size - 0xBC0

    third_key_off = 0x968 + ss_shift
    forth_key_off = 0x964 + ss_shift
    cs_base_off = 0x96C + ss_shift
    dp_base_off = 0xA9C + ss_shift

    # ThirdStage (in-place, shift search)
    third_pair_off = 0xB8C + ss_shift
    key = u32(data, ss + third_key_off)
    pair_addr = ss + third_pair_off
    ts_addr = u32(data, pair_addr)
    ts_size_raw = u32(data, pair_addr + 4)
    backup = bytearray(data[ts_addr:ts_addr + ts_size_raw])
    ts = info_table = keys_addr = None
    for shift in (19, 21, 17, 23, 15, 25, 13, 11):
        data[ts_addr:ts_addr + ts_size_raw] = backup
        d.w32(data, pair_addr, ts_addr)
        d.w32(data, pair_addr + 4, ts_size_raw)
        d.decrypt_data3(data, pair_addr, key, shift)
        for off in range(0, ts_size_raw - 32, 4):
            if u32(data, ts_addr + off) in (1, 0x11) and u32(data, ts_addr + off + 16) == 2:
                addr0 = u32(data, ts_addr + off + 4)
                if 0x1000 < addr0 < len(data):
                    info_table = ts_addr + off
                    keys_addr = info_table - 0x58
                    ts = ts_addr
                    break
        if ts is not None:
            break
    if ts is None:
        raise ValueError('cannot decrypt thirdStage (PE32)')

    data4_va = u32(data, info_table + 4)
    data4_sz = u32(data, info_table + 8)

    it = info_table
    for _ in range(2):
        tval = u32(data, it)
        if tval in (1, 0x11):
            d.decrypt_data4(data, it + 4)
        elif tval == 2:
            ca = u32(data, it + 4)
            while True:
                d.decrypt_data5(data, ca, 16)
                s_a, s_sz = u32(data, ca), u32(data, ca + 4)
                d_a, d_sz = u32(data, ca + 8), u32(data, ca + 12)
                ca += 16
                if s_sz == 0:
                    break
                if s_a and d_a and d_sz == s_sz:
                    data[d_a:d_a + s_sz] = data[s_a:s_a + s_sz]
        it += 16
    key_offsets = [0] * 4
    ka = keys_addr
    for k in range(2):
        ka2 = ka
        for l in range(2):
            d.decrypt_data4(data, ka2)
            key_offsets[k * 2 + l] = u32(data, ka2)
            ka2 += 8
        ka += 32

    second_stage_cs_addr = tbl + 0xB0
    forth_cs_addr = ss + cs_base_off
    fifth_cs_addr = ss + cs_base_off + 0x08
    seven_cs_addr = ss + cs_base_off + 0x10
    dp_base = ss + dp_base_off

    # Forth
    second_stage_cs = d.checksum_with_size_xor(data, second_stage_cs_addr)
    forth_key = d.advance_key(u32(data, ss + forth_key_off), 4)
    fk4 = (header_checksum ^ second_stage_cs ^ forth_key) & 0xFFFFFFFF
    d.decrypt_and_decompress(data, dp_base + 0x40, fk4, key_offsets)
    # Fifth
    forth_cs = d.checksum_with_size_xor(data, forth_cs_addr)
    fro = u32(data, forth_cs_addr); frs = u32(data, forth_cs_addr + 4)
    fifth_key = u32(data, fro + frs - 4)
    fk5 = (header_checksum ^ forth_cs ^ fifth_key) & 0xFFFFFFFF
    d.decrypt_and_decompress(data, dp_base + 0x50, fk5, key_offsets)
    # Seven
    fifth_cs = d.checksum_with_size_xor(data, fifth_cs_addr)
    cs1_addr = u32(data, fifth_cs_addr); cs1_size = u32(data, fifth_cs_addr + 4)
    seven_key = (~u32(data, cs1_addr + cs1_size - 0x10)) & 0xFFFFFFFF
    fk7 = (header_checksum ^ fifth_cs ^ seven_key) & 0xFFFFFFFF
    seven_addr = dp_base + 0x70
    d.decrypt_and_decompress(data, seven_addr, fk7, key_offsets)
    seven_start = u32(data, seven_addr)
    seven_dsz = u32(data, seven_addr + 12)
    cdo_off = d.find_lfsr_block(data, seven_start, seven_dsz, max(0, seven_dsz // 2), scan_backward=True)
    if cdo_off is None:
        cdo_off = d.find_lfsr_block(data, seven_start, seven_dsz, 0)
    d.decrypt_data6(data, seven_start + cdo_off)
    stage_custom_dec = d.generate_custom_decryptor(data, seven_start + cdo_off)

    # Eighth (brute-force key)
    seven_cs = d.checksum_with_size_xor(data, seven_cs_addr)
    eighth_addr = dp_base + 0xC0
    eighth_dsz = u32(data, eighth_addr + 12)
    eighth_src = u32(data, eighth_addr); eighth_ssz = u32(data, eighth_addr + 4)
    eb = bytearray(data[eighth_src:eighth_src + eighth_ssz])
    epb = bytearray(data[eighth_addr:eighth_addr + 16])
    ekc = []
    for end_gap in [0xD0, 0xC0, 0xE0, 0xB0, 0xA0, 0xF0, 0x100]:
        off = seven_dsz - end_gap
        if 0 <= off < seven_dsz and u32(data, seven_start + off) not in (0, 0xCCCCCCCC):
            ekc.append(off)
    for gap in [0x70, 0xD0, 0x28, 0x50, 0x48, 0x30, 0x40, 0x58, 0x60, 0x20, 0x38, 0x80, 0x90, 0xA0, 0xB0]:
        off = cdo_off - gap
        if 0 <= off and off + 4 <= seven_dsz and off not in ekc and u32(data, seven_start + off) not in (0, 0xCCCCCCCC):
            ekc.append(off)
    for off in range(max(0, cdo_off - 0x100), cdo_off, 4):
        if off not in ekc:
            v = u32(data, seven_start + off)
            if v not in (0, 0xCCCCCCCC) and not all(32 <= ((v >> (i * 8)) & 0xFF) < 127 for i in range(4)):
                ekc.append(off)
    ok = False
    for off in ekc:
        data[eighth_src:eighth_src + eighth_ssz] = eb
        data[eighth_addr:eighth_addr + 16] = epb
        fk8 = (header_checksum ^ fifth_cs ^ seven_cs ^ d.advance_key(u32(data, seven_start + off), 3)) & 0xFFFFFFFF
        try:
            if d.decrypt_and_decompress(data, eighth_addr, fk8, key_offsets, stage_custom_dec, verbose=False) \
                    and 0x1000 < u32(data, eighth_addr) < len(data):
                ok = True
                break
        except Exception:
            pass
    if not ok:
        raise ValueError('cannot decrypt eighthStage (PE32)')
    eighth_start = u32(data, eighth_addr)
    eighth_dsz = u32(data, eighth_addr + 12)

    # Fixed table offsets
    off_file_cs = 0x3C68 + ss_shift
    off_compressed_info = 0x3C78 + ss_shift
    off_zero_list = 0x3C80 + ss_shift
    off_file_lfsr = 0x40EC + ss_shift

    compress_data_offset = ((~u32(file_data, 0x1080)) & 0xFFFFFFFF) + 0x1000

    # File checksums
    file_cs_addr = u32(data, eighth_start + off_file_cs)
    file_cs_size = u32(data, eighth_start + off_file_cs + 4)
    if file_cs_size > 0:
        fc_end = file_cs_addr + file_cs_size
        fc = file_cs_addr
        while fc < fc_end:
            d.decrypt_data5(data, fc, 16)
            fc += 16
    else:
        fc = file_cs_addr
        while u32(data, fc + 4) != 0:
            d.decrypt_data5(data, fc, 16)
            fc += 16

    # File LFSR (validate fixed offset, fallback scan)
    lfsr_off = off_file_lfsr
    found = d.find_lfsr_block(data, eighth_start, eighth_dsz, lfsr_off)
    if found != lfsr_off:
        valid_op = {0x04, 0x2C, 0x34, 0x90, 0xC0, 0xC3, 0xFE}
        cands = []
        for so in range(off_zero_list, eighth_dsz - 95):
            ab = eighth_start + so
            sz = data[ab + 95]
            if sz < 10 or sz > 95:
                continue
            lf = 1
            dec = bytearray(sz)
            src = data[ab:ab + sz]
            for bi in range(sz):
                b = src[bi]
                for bit in range(8):
                    b ^= ((lf & 1) << bit)
                    lf <<= 1
                    if lf & 0x8000:
                        lf ^= 0x8003
                    lf &= 0xFFFF
                dec[bi] = b
            if dec[0] in valid_op and 0xC3 in dec:
                cands.append(so)
        if cands:
            exact = [c for c in cands if c == off_file_lfsr]
            neg = sorted([c for c in cands if c < off_file_lfsr], key=lambda c: off_file_lfsr - c)
            pos = sorted([c for c in cands if c > off_file_lfsr], key=lambda c: c - off_file_lfsr)
            lfsr_off = exact[0] if exact else (neg[0] if neg else pos[0])
        else:
            raise ValueError('cannot locate file LFSR (PE32)')
    file_dec_addr = eighth_start + lfsr_off
    d.decrypt_data6(data, file_dec_addr)
    file_dec = d.generate_custom_decryptor(data, file_dec_addr)
    if file_dec is None:
        raise ValueError('cannot generate file decryptor (PE32)')

    meta = _capture_metadata(data, info[3], image_size)

    # zeroList runs BEFORE the file loop (PE32).
    zero_ptr = u32(data, eighth_start + off_zero_list)
    while True:
        d.decrypt_data5(data, zero_ptr, 16)
        z_src = u32(data, zero_ptr); z_sz = u32(data, zero_ptr + 4)
        zero_ptr += 16
        if z_sz == 0:
            break
        if z_src + z_sz > len(data):
            break
        data[z_src:z_src + z_sz] = b'\x00' * z_sz

    compressed_info_addr = u32(data, eighth_start + off_compressed_info)
    compressed_records = []
    ci = compressed_info_addr
    while True:
        d.decrypt_data5(data, ci, 16)
        s2, ss2 = u32(data, ci), u32(data, ci + 4)
        d2, ds2 = u32(data, ci + 8), u32(data, ci + 12)
        ci += 16
        if ss2 == 0:
            break
        compressed_records.append((s2, ss2, d2, ds2))
        fsrc = s2 + compress_data_offset
        data[d2:d2 + ss2] = file_data[fsrc:fsrc + ss2]
        d.aes_decrypt(data, d2, ss2, key_offsets[2])
        _lut, tt = file_dec
        data[d2:d2 + ss2] = bytearray(bytes(data[d2:d2 + ss2]).translate(tt))
        if ss2 != ds2:
            d.decompress(data, d2, d2, key_offsets[0], ss2, ds2)
    decoded_image = bytearray(data)

    prof = TemplateProfile()
    prof.info = info
    prof.pe = pe
    prof.image_size = image_size
    prof.decrypt_size = decrypt_size
    prof.compress_data_offset = compress_data_offset
    prof.raw_shell = raw_shell
    prof.decoded_image = decoded_image
    prof.key_offsets = key_offsets
    prof.eighth_start = eighth_start
    prof.file_dec = file_dec
    prof.compressed_info_addr = compressed_info_addr
    prof.compressed_records = compressed_records
    prof.file_cs_addr = file_cs_addr
    prof.data4_va = data4_va
    prof.data4_sz = data4_sz
    if meta is not None:
        prof.meta_off, prof.meta_size, prof.meta_ep_rel, prof.meta_plain, prof.meta_ep = meta
    return prof


def restore_identity(prof, file_data):
    """Full-fidelity reconstruction: regenerate info[], the Data2 shell, and the
    compressedInfo records FROM THE PARSED VALUES (not copied), keep the original
    compressed payload + section layout, and emit. If every primitive is an exact
    inverse, the result is byte-identical to the original packed file
    (encrypt(decrypt(X)) == X). This regenerates the control tables rather than
    copying them, proving exact table reconstruction."""
    info = prof.info
    raw_shell = bytearray(prof.raw_shell)
    # Regenerate the compressedInfo records from the decoded values, re-applying
    # the Data5 (inner) then Data4 (outer) layers at their addresses. This must
    # reproduce the original encrypted record bytes exactly.
    base = prof.compressed_info_addr
    for j, rec in enumerate(prof.compressed_records):
        off = base + j * 16
        enc5 = e.encrypt_data5_record(struct.pack('<IIII', *rec), off)
        raw_shell[off:off + 16] = enc5
        e.encrypt_data4_at(raw_shell, off, 16, prof.data4_va)
    # Regenerate the metadata block too (from its parsed plaintext) if captured.
    if prof.meta_plain is not None:
        enc5 = e.encrypt_data5_record(bytes(prof.meta_plain), prof.meta_off)
        raw_shell[prof.meta_off:prof.meta_off + prof.meta_size] = enc5
        e.encrypt_data4_at(raw_shell, prof.meta_off, prof.meta_size, prof.data4_va)

    out = bytearray(file_data)  # keep payload + section pages + tail verbatim
    out[0x1000:0x1020] = e.encrypt_data1_info(info)
    shell_src = info[4] + 0x1000
    enc_shell = e.encrypt_data2_shell(
        raw_shell[info[3]:info[3] + prof.decrypt_size], info, prof.decrypt_size)
    out[shell_src:shell_src + len(enc_shell)] = enc_shell
    return bytes(out)


def cmd_restore(path, aes_dir):
    load_tables(aes_dir)
    file_data = bytearray(path.read_bytes())
    prof = unpack_template(file_data)
    out = restore_identity(prof, file_data)
    fd = first_diff(out, bytes(file_data))
    if fd < 0:
        print(f'RESTORE PASS: encrypt(decrypt({path.name})) is BYTE-IDENTICAL to '
              f'the original (len 0x{len(out):X})')
        print(f'  regenerated {len(prof.compressed_records)} compressedInfo records'
              f' + metadata + info[] + Data2 shell from parsed values')
        return 0
    # report
    info = prof.info
    decrypt_size = prof.decrypt_size
    shell_src = info[4] + 0x1000
    region = 'info[]' if 0x1000 <= fd < 0x1020 else (
        'Data2-shell' if shell_src <= fd < shell_src + decrypt_size else 'payload/other')
    print(f'RESTORE DIFF at file 0x{fd:X} ({region})')
    lo = max(0, fd - 8)
    print(f'  orig: {bytes(file_data[lo:fd + 8]).hex()}')
    print(f'  ours: {bytes(out[lo:fd + 8]).hex()}')
    return 1


def _verify_decoded_image(prof, repacked_bytes, extra_allowed=None):
    """Arch-agnostic verification: re-parse the repacked file and compare its
    decoded program image to the template's. All diffs must lie inside the
    compressedInfo record table (rewritten on purpose) or any explicit patch
    regions. Avoids the PE32 compaction mismatch that breaks a raw .unpack
    byte-compare."""
    prof2 = unpack_template(bytearray(repacked_bytes))
    a, b = prof.decoded_image, prof2.decoded_image
    n = min(len(a), len(b))
    diffs = []
    i = 0
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            diffs.append((i, j))
            i = j
        else:
            i += 1
    if len(a) != len(b):
        diffs.append((n, max(len(a), len(b))))
    total = sum(y - x for x, y in diffs)
    ci = prof.compressed_info_addr
    ci_end = ci + (len(prof.compressed_records) + 1) * 16
    # The packed PE header [0:0x1000] is loader bookkeeping (section-table
    # PtrRaw is rewritten by section relocation; the decryptor restores the real
    # program header from metadata later), so it is not part of the program.
    allowed = [(0, 0x1000), (ci, ci_end)]
    allowed += [(s, s + sz) for s, sz in (extra_allowed or [])]
    esc = [(x, y) for x, y in diffs
           if not any(lo <= x and y <= hi for lo, hi in allowed)]
    print(f'  decoded-image: {len(diffs)} diff ranges, {total} bytes')
    if not esc:
        extra = '' if not extra_allowed else ' + patch region(s)'
        print(f'  VERIFY OK: decoded program image identical outside'
              f' compressedInfo table{extra}')
        return True
    print(f'  VERIFY FAIL: {len(esc)} range(s) escape allowed regions')
    for x, y in esc[:6]:
        print(f'    escape 0x{x:X}..0x{y:X}')
    return False


def encode_block_nolz(plaintext, aes_ek, file_dec, inv_tt=None):
    """Build the on-disk bytes for a no-LZ (s_size==d_size) file block from its
    decoded plaintext: inverse-LFSR-translate, then AES-CBC encrypt with the
    pre-derived forward round keys `aes_ek`. Inverse of the decryptor file-loop
    decode (copy -> aes_decrypt -> translate) when s_size==d_size. Pass a
    precomputed `inv_tt` (inverse translate table) to avoid rebuilding it per
    block."""
    if inv_tt is None:
        inv_tt = e.inverse_translate_table(file_dec)
    buf = bytearray(bytes(plaintext).translate(inv_tt))
    e.aes_encrypt_cbc_ek(buf, 0, len(buf), aes_ek)
    return bytes(buf)


def encode_block(plaintext, aes_ek, file_dec, inv_tt, lz_sym2code):
    """Encode a file block, choosing real LZ compression when it shrinks the
    block, else falling back to no-LZ (s_size==d_size). Returns (bytes, s_size).
    Encode pipeline mirrors the decoder in reverse: (LZ compress ->) inverse
    LFSR-translate -> AES-CBC encrypt (full 16-byte blocks; tail untouched)."""
    d_size = len(plaintext)
    if lz_sym2code is not None:
        try:
            comp, s_size = lz.compress(bytes(plaintext), lz_sym2code)
        except lz.CompressError:
            comp, s_size = None, d_size
        if comp is not None and s_size < d_size:
            buf = bytearray(bytes(comp).translate(inv_tt))
            e.aes_encrypt_cbc_ek(buf, 0, s_size, aes_ek)
            return bytes(buf), s_size
    buf = bytearray(bytes(plaintext).translate(inv_tt))
    e.aes_encrypt_cbc_ek(buf, 0, d_size, aes_ek)
    return bytes(buf), d_size


def cmd_parse(path, aes_dir):
    load_tables(aes_dir)
    file_data = bytearray(path.read_bytes())
    prof = unpack_template(file_data)
    recs = prof.compressed_records
    nlz = sum(1 for s, ss, ds, dd in recs if ss != dd)
    print(f'parse {path.name}:')
    print(f'  image_size           = 0x{prof.image_size:X}')
    print(f'  compress_data_offset = 0x{prof.compress_data_offset:X}')
    print(f'  key_offsets          = [{", ".join(f"0x{x:X}" for x in prof.key_offsets)}]')
    print(f'  eighth_start         = 0x{prof.eighth_start:X}')
    print(f'  compressedInfo @ 0x{prof.compressed_info_addr:X}, {len(recs)} blocks '
          f'({nlz} LZ-compressed, {len(recs)-nlz} stored)')
    print(f'  fileCS @ 0x{prof.file_cs_addr:X}')

    # Self-check: no-LZ encode then decode (in a scratch image, where the AES
    # decrypt schedule is in place) must round-trip back to the plaintext.
    aes_ek = e.derive_aes_encrypt_keys(prof.decoded_image, prof.key_offsets[2])
    _lut, tt = prof.file_dec
    scratch = bytearray(prof.decoded_image)
    checked = 0
    for (s, ss, dst, dd) in recs[:40]:
        plain = bytes(prof.decoded_image[dst:dst + dd])
        blk = encode_block_nolz(plain, aes_ek, prof.file_dec)
        assert len(blk) == dd
        scratch[dst:dst + dd] = blk
        d.aes_decrypt(scratch, dst, dd, prof.key_offsets[2])
        scratch[dst:dst + dd] = bytes(scratch[dst:dst + dd]).translate(tt)
        assert bytes(scratch[dst:dst + dd]) == plain, f'roundtrip failed dst=0x{dst:X}'
        checked += 1
    print(f'  no-LZ encode roundtrip OK on {checked} blocks')
    return 0


def repack_same_image(prof, file_data, nolz_set, patches=None, corrupt_record=None,
                      use_lz=False, set_ep=None):
    """Re-emit a packed file for the SAME decoded image, emitting the blocks in
    `nolz_set` as uncompressed (s_size==d_size) and copying every other block's
    original compressed bytes verbatim. Block COUNT is preserved (the zeroList
    table immediately follows compressedInfo in memory, so the count must not
    change). Only free regions are touched -> no checksum/key recomputation.

    `patches` (optional): list of (rva, bytes) applied to the decoded image
    before re-encoding. Patched blocks are forced into nolz_set (we can only
    re-encode no-LZ, not LZ-compress).
    `corrupt_record` (optional): (j, (src,ss,dst,dd)) override of the STORED
    table record j only (payload block stays valid). For runtime probing."""
    info = prof.info
    cdo = prof.compress_data_offset
    raw_shell = bytearray(prof.raw_shell)
    aes_ek = e.derive_aes_encrypt_keys(prof.decoded_image, prof.key_offsets[2])
    recs = prof.compressed_records

    image = bytearray(prof.decoded_image)
    nolz_set = set(nolz_set)
    if patches:
        for rva, data_bytes in patches:
            image[rva:rva + len(data_bytes)] = data_bytes
            # any block whose dst range intersects the patch must be re-encoded
            for j, (s, ss, dst, dd) in enumerate(recs):
                if dst < rva + len(data_bytes) and rva < dst + dd:
                    nolz_set.add(j)

    inv_tt = e.inverse_translate_table(prof.file_dec)
    lz_sym2code = None
    if use_lz:
        lz_sym2code = lz.parse_huffman(prof.decoded_image, prof.key_offsets[0])
    payload = bytearray()
    new_records = []
    for j, (s, ss, dst, dd) in enumerate(recs):
        if j in nolz_set:
            if use_lz:
                blk, new_ss = encode_block(image[dst:dst + dd], aes_ek,
                                           prof.file_dec, inv_tt, lz_sym2code)
            else:
                blk = encode_block_nolz(image[dst:dst + dd], aes_ek, prof.file_dec, inv_tt)
                new_ss = dd
        else:
            o = s + cdo
            blk = bytes(file_data[o:o + ss])
            new_ss = ss
        while len(payload) % 4:        # 4-align srcs like the original
            payload.append(0)
        new_src = len(payload)
        payload.extend(blk)
        new_records.append((new_src, new_ss, dst, dd))

    if corrupt_record is not None:
        j, override = corrupt_record
        new_records[j] = override

    # Optionally rewrite the entry point in the metadata block (double-encrypted
    # Data4 outer / Data5 inner, like the tables). Written BEFORE compressedInfo
    # so that on layout-B samples the compressedInfo records (which overlap the
    # metadata block's padding tail) win in the overlap.
    if set_ep is not None:
        if prof.meta_plain is None:
            raise ValueError('metadata not captured; cannot set EP')
        mbuf = bytearray(prof.meta_plain)
        struct.pack_into('<I', mbuf, prof.meta_ep_rel, set_ep & 0xFFFFFFFF)
        enc5 = e.encrypt_data5_record(bytes(mbuf), prof.meta_off)
        raw_shell[prof.meta_off:prof.meta_off + prof.meta_size] = enc5
        e.encrypt_data4_at(raw_shell, prof.meta_off, prof.meta_size, prof.data4_va)

    # Rewrite the compressedInfo records in place (same addresses, same count).
    # The control tables are stored DOUBLE-encrypted in the Data2 shell:
    # decode is decrypt_data4 (outer, region-wide) then decrypt_data5 (inner,
    # per-record). So encode is encrypt_data5 (inner) then encrypt_data4 (outer).
    base = prof.compressed_info_addr
    if not (prof.data4_va <= base and base + len(new_records) * 16 <= prof.data4_va + prof.data4_sz):
        raise ValueError('compressedInfo records fall outside the Data4 region')
    for j, rec in enumerate(new_records):
        off = base + j * 16
        rec_bytes = struct.pack('<IIII', *rec)
        enc5 = e.encrypt_data5_record(rec_bytes, off)   # inner layer (va=off)
        raw_shell[off:off + 16] = enc5
        e.encrypt_data4_at(raw_shell, off, 16, prof.data4_va)  # outer layer

    out = bytearray(file_data[:cdo]) + bytes(payload)
    out[0x1000:0x1020] = e.encrypt_data1_info(info)
    shell_src = info[4] + 0x1000
    enc_shell = e.encrypt_data2_shell(
        raw_shell[info[3]:info[3] + prof.decrypt_size], info, prof.decrypt_size)
    out[shell_src:shell_src + len(enc_shell)] = enc_shell
    # The packed PE keeps its 6 one-page sections at the very END of the file
    # (after the compressed payload); the Windows loader maps them from PtrRaw,
    # while the stub reads info/Data2/payload by fixed file offsets. Our rebuilt
    # payload is a different size, so relocate the section pages to just after it
    # and fix PtrRaw. (Section table sits past the checksummed header bytes.)
    relocate_sections(out, file_data, prof.pe)
    return bytes(out)


def relocate_sections(out, file_data, pe):
    """Append the packed PE's raw section pages after the current payload and
    update each PtrRaw. Keeps the loader able to map sections while the stub's
    file-offset reads (info/Data2/payload) stay where they are."""
    opt_size = u16(file_data, pe + 20)
    nsec = u16(file_data, pe + 6)
    file_align = u32(file_data, pe + 24 + 36)
    sectab = pe + 24 + opt_size
    ptrs = []
    smin = None
    smax = 0
    for i in range(nsec):
        s = sectab + i * 40
        rp = u32(file_data, s + 20)
        rsz = u32(file_data, s + 16)
        ptrs.append((s, rp, rsz))
        if rp and rsz:
            smin = rp if smin is None else min(smin, rp)
            smax = max(smax, rp + rsz)
    if smin is None:
        return
    section_data = file_data[smin:smax]
    # align file size to FileAlignment before placing the section block
    if len(out) % file_align:
        out.extend(b'\x00' * (file_align - (len(out) % file_align)))
    new_base = len(out)
    out.extend(section_data)
    for s, rp, rsz in ptrs:
        if rp and rsz:
            d.w32(out, s + 20, new_base + (rp - smin))


def _verify_roundtrip(repacked_bytes, reference_unpack, aes_dir, tag, prof=None,
                      extra_allowed=None):
    """Write the repacked file, run decrypt_crackproof on it, and compare the
    unpacked result against the known-good reference unpack. Diffs are EXPECTED
    inside the compressedInfo record table (we rewrote it to reflect the new
    block layout) and inside any `extra_allowed` (start,size) regions (e.g.
    explicit content patches); the test passes when every diff is confined to
    those regions and the rest of the reconstructed program is byte-identical."""
    import subprocess
    import tempfile
    tmp = Path(tempfile.gettempdir()) / f'crackproof_{tag}.exe'
    tmp.write_bytes(repacked_bytes)
    unpacked = tmp.with_name(tmp.stem + '.unpack.exe')
    if unpacked.exists():
        unpacked.unlink()
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH), str(tmp), str(aes_dir)],
        capture_output=True, text=True)
    if not unpacked.exists():
        print('  decryptor did not produce output. stderr/stdout tail:')
        for line in (proc.stdout + proc.stderr).splitlines()[-15:]:
            print('   ', line)
        return False
    got = unpacked.read_bytes()
    ref = Path(reference_unpack).read_bytes()
    if got == ref:
        print(f'  ROUND-TRIP OK: unpack(repacked) == {Path(reference_unpack).name}'
              f' (0x{len(got):X} bytes, BYTE-IDENTICAL)')
        return True
    if len(got) != len(ref):
        print(f'  ROUND-TRIP FAIL: length differs got=0x{len(got):X} ref=0x{len(ref):X}')
        return False

    # Collect all differing byte ranges.
    diffs = []
    i = 0
    n = len(got)
    while i < n:
        if got[i] != ref[i]:
            j = i
            while j < n and got[j] != ref[j]:
                j += 1
            diffs.append((i, j))
            i = j
        else:
            i += 1
    total = sum(b - a for a, b in diffs)
    lo = min(a for a, b in diffs)
    hi = max(b for a, b in diffs)
    print(f'  diffs: {len(diffs)} ranges, {total} bytes, span 0x{lo:X}..0x{hi:X}')
    for a, b in diffs[:6]:
        print(f'    0x{a:X}..0x{b:X} (0x{b-a:X})')
    if len(diffs) > 6:
        print(f'    ... ({len(diffs)-6} more)')

    if prof is not None:
        # The compressedInfo table occupies [addr : addr + (n_records+1)*16]
        # (+1 for the zero terminator). Diffs must be confined to it, plus any
        # explicitly-allowed patch regions.
        ci = prof.compressed_info_addr
        ci_end = ci + (len(prof.compressed_records) + 1) * 16
        allowed = [(ci, ci_end)]
        for st, sz in (extra_allowed or []):
            allowed.append((st, st + sz))

        def _ok(a, b):
            return any(lo <= a and b <= hi for lo, hi in allowed)

        confined = all(_ok(a, b) for a, b in diffs)
        if confined:
            extra = '' if not extra_allowed else ' + patch region(s)'
            print(f'  ROUND-TRIP OK*: all diffs confined to compressedInfo table'
                  f'{extra} (program identical outside)')
            return True
        escapes = [(a, b) for a, b in diffs if not _ok(a, b)]
        print(f'  ROUND-TRIP FAIL: {len(escapes)} diff range(s) ESCAPE allowed'
              f' regions -> program bytes changed unexpectedly!')
        for a, b in escapes[:6]:
            print(f'    escape 0x{a:X}..0x{b:X}')
        return False
    return False


def cmd_m2(path, aes_dir):
    load_tables(aes_dir)
    file_data = bytearray(path.read_bytes())
    prof = unpack_template(file_data)
    # pick the first LZ-compressed block to swap to no-LZ
    target = next((j for j, (s, ss, ds, dd) in enumerate(prof.compressed_records)
                   if ss != dd), None)
    if target is None:
        print('M2: no LZ-compressed block found')
        return 1
    s, ss, dst, dd = prof.compressed_records[target]
    print(f'M2: swap block #{target} (src=0x{s:X} s_size=0x{ss:X} dst=0x{dst:X}'
          f' d_size=0x{dd:X}) -> no-LZ')
    out = repack_same_image(prof, file_data, {target})
    print(f'  repacked size 0x{len(out):X} (orig 0x{len(file_data):X})')
    ref = path.with_name(path.stem + '.unpack' + path.suffix)
    ok = _verify_roundtrip(out, ref, aes_dir, 'm2', prof)
    # also save the repacked file next to the sample for runtime testing
    savep = path.with_name(path.stem + '.repack_m2' + path.suffix)
    savep.write_bytes(out)
    print(f'  saved {savep.name}')
    return 0 if ok else 1


def cmd_m3(path, aes_dir):
    load_tables(aes_dir)
    file_data = bytearray(path.read_bytes())
    prof = unpack_template(file_data)
    nolz = set(range(len(prof.compressed_records)))
    print(f'M3: repack same image with all {len(nolz)} blocks no-LZ')
    out = repack_same_image(prof, file_data, nolz)
    print(f'  repacked size 0x{len(out):X} (orig 0x{len(file_data):X})')
    ref = path.with_name(path.stem + '.unpack' + path.suffix)
    ok = _verify_roundtrip(out, ref, aes_dir, 'm3', prof)
    savep = path.with_name(path.stem + '.repack_m3' + path.suffix)
    savep.write_bytes(out)
    print(f'  saved {savep.name}')
    return 0 if ok else 1


def cmd_breaktext(path, aes_dir):
    """Control experiment: fill the entire .text with 0xCC (int3) in the decoded
    image, repack no-LZ, and save. If the program is truly executed at runtime,
    this MUST crash/terminate differently than the clean repack (which exits 0).
    Proves the reconstructed program bytes are actually run."""
    load_tables(aes_dir)
    file_data = bytearray(path.read_bytes())
    prof = unpack_template(file_data)
    pe = prof.pe
    opt = u16(file_data, pe + 20)
    sectab = pe + 24 + opt
    nsec = u16(file_data, pe + 6)
    text_va = text_vs = 0
    for i in range(nsec):
        s = sectab + i * 40
        if file_data[s:s + 5] == b'.text':
            text_vs = u32(file_data, s + 8)
            text_va = u32(file_data, s + 12)
            break
    if not text_va:
        print('breaktext: no .text section')
        return 1
    print(f'breaktext: filling .text [0x{text_va:X}..0x{text_va+text_vs:X}] with 0xCC')
    patches = [(text_va, b'\xCC' * text_vs)]
    out = repack_same_image(prof, file_data, set(), patches=patches)
    savep = path.with_name(path.stem + '.break' + path.suffix)
    savep.write_bytes(out)
    print(f'  saved {savep.name} (size 0x{len(out):X})')
    return 0


def cmd_badblock(path, aes_dir):
    """Runtime probe: build a repack where block #0 (the FIRST file block the
    stub processes) is no-LZ but its stored dst points to UNMAPPED memory
    (0x40000000, far past the 0xA51000 image). If the native stub reaches the
    file-block loop, the very first block's copy writes to an unmapped address
    -> immediate access violation. If it still exits 0 like a clean repack, the
    env-exit fires BEFORE the file-block loop. Fast build (only block #0 no-LZ)."""
    load_tables(aes_dir)
    file_data = bytearray(path.read_bytes())
    prof = unpack_template(file_data)
    s, ss, dst, dd = prof.compressed_records[0]
    override = (0, 0x1000, 0x40000000, 0x1000)  # no-LZ copy to unmapped dst
    print(f'badblock: record #0 dst -> 0x40000000 (unmapped); was dst=0x{dst:X}')
    out = repack_same_image(prof, file_data, {0}, corrupt_record=(0, override))
    savep = path.with_name(path.stem + '.badblock' + path.suffix)
    savep.write_bytes(out)
    print(f'  saved {savep.name} (size 0x{len(out):X})')
    return 0


def first_diff(a, b):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return n
    return -1


def cmd_m0(path, aes_dir):
    load_tables(aes_dir)
    file_data = bytearray(path.read_bytes())
    out = reemit_outer_identity(file_data)
    fd = first_diff(out, bytes(file_data))
    if fd < 0:
        print(f'M0 PASS: re-emitted {path.name} is BYTE-IDENTICAL to original'
              f' (len 0x{len(out):X})')
        return 0
    # Report what diverged.
    info = d.decrypt_data1(file_data)
    pe = u32(file_data, 0x3C)
    decrypt_size = info[6] - info[3] + 0x2000
    shell_src = info[4] + 0x1000
    region = 'info[]' if 0x1000 <= fd < 0x1020 else (
        'Data2-shell' if shell_src <= fd < shell_src + decrypt_size else 'OTHER')
    print(f'M0 FAIL: first diff at file 0x{fd:X} ({region})')
    lo = max(0, fd - 8)
    print(f'  orig: {bytes(file_data[lo:fd+8]).hex()}')
    print(f'  ours: {bytes(out[lo:fd+8]).hex()}')
    return 1


# ======================================================================
# ==== merged from pack.py
# ======================================================================




# Bundled universal stub profile (extracted once from a real CrackProof sample).
# This is the irreducible "borrowed stub" data; the AES tables are generated in
# code, so packing needs only this file + the target program.
BUNDLED_PROFILE = Path(__file__).resolve().parent / 'stub_profile.bin'


def _load_profile(path):
    """Load a stub profile blob, transparently handling zlib-compressed bundles
    (the shipped stub_profile.bin) and raw pickle (legacy extract output)."""
    raw = Path(path).read_bytes()
    try:
        raw = zlib.decompress(raw)
    except zlib.error:
        pass
    return pickle.loads(raw)


def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]
def w32(b, o, v): struct.pack_into('<I', b, o, v & 0xFFFFFFFF)


# ----------------------------------------------------------------- target PE parse
def parse_target(T):
    """Parse an unpacked PE32+: returns dict with pe, image_size, ep, dirs(128B),
    sections list, import_rva/size. T is the full RVA image (file_off == RVA)."""
    pe = u32(T, 0x3C)
    if u16(T, pe + 24) != 0x20B:
        raise ValueError('target is not PE32+')
    opt = u16(T, pe + 20)
    nsec = u16(T, pe + 6)
    sectab = pe + 24 + opt
    sections = []
    for i in range(nsec):
        s = sectab + i * 40
        sections.append({
            'name': bytes(T[s:s + 8]),
            'vs': u32(T, s + 8), 'va': u32(T, s + 12),
            'rawsz': u32(T, s + 16), 'rawptr': u32(T, s + 20),
            'chars': u32(T, s + 36), 'hdr': s,
        })
    return {
        'pe': pe, 'opt': opt, 'nsec': nsec, 'sectab': sectab,
        'image_size': u32(T, pe + 80),
        'ep': u32(T, pe + 40),
        'dirs': bytes(T[pe + 0x88:pe + 0x88 + 128]),
        'import_rva': u32(T, pe + 0x90), 'import_size': u32(T, pe + 0x94),
        'sections': sections,
    }


def encrypt_target_imports(img, tgt):
    """Data7-encrypt the target's import DLL/function names in `img` so the stub's
    decrypt_data7 recovers them. Mirrors the decryptor's name walk."""
    irva = tgt['import_rva']
    if not irva:
        return 0
    n = len(img)
    pos = irva
    count = 0
    while pos + 20 <= n:
        name_rva = u32(img, pos + 12)
        oft = u32(img, pos)
        iat = u32(img, pos + 16)
        if name_rva == 0 and oft == 0 and iat == 0:
            break
        if 0 < name_rva < n:
            e.encrypt_data7(img, name_rva, name_rva & 0xFF)
        thunk = oft if oft else iat
        while thunk and thunk + 8 <= n:
            v = struct.unpack_from('<Q', img, thunk)[0]
            if v == 0:
                break
            if not (v & 0x8000000000000000):
                rv = v & 0xFFFFFFFF
                if 0 < rv + 2 < n:
                    e.encrypt_data7(img, rv + 2, rv & 0xFF)
            thunk += 8
        count += 1
        pos += 20
    return count


# Cross-layout carry: the packed PHYSICAL header stays donor-compatible (so
# Windows loads the file and runs the stub), but decrypt needs the TARGET's
# section table to emit a valid final PE. We append the target's section table +
# image sizing as an EOF overlay trailer. decrypt parses it the instant it reads
# the file (before any in-place transform), so later clobbering is irrelevant;
# the PE loader ignores overlay and the payload decoder uses explicit offsets, so
# nothing reads to EOF. Only emitted for cross packs -> identity output unchanged
# and stock CrackProof samples (no trailer) are handled unchanged by decrypt.
_TGT_HDR_MAGIC = b'CPXSECT\x00'


def _build_target_hdr_trailer(T):
    """EOF trailer carrying the target's NumberOfSections / SizeOfImage /
    SizeOfHeaders / raw section table AND the target's verbatim header region
    [0:SizeOfHeaders], so decrypt can rebuild the final PE header byte-for-byte
    (incl. the target's own e_lfanew + DOS stub) even when the shell stub has a
    different header layout (e.g. Sinmai e_lfanew=0x110 packed with an amdaemon
    stub e_lfanew=0x128).
    Layout: payload + crc32(payload)[4] + len(payload)[4] + MAGIC[8].
    payload = <IIII nsec,simg,shdr,flags> + sectbl + <I hdrlen> + hdrbytes
    (hdrlen/hdrbytes are an optional tail; old parsers stop after sectbl).
    flags bit0 = SKIP_D8 (embedded .text is final plaintext)."""
    pe = u32(T, 0x3C)
    optsz = u16(T, pe + 0x14)
    nsec = u16(T, pe + 6)
    simg = u32(T, pe + 0x50)
    shdr = u32(T, pe + 0x54)
    st = pe + 0x18 + optsz
    sectbl = bytes(T[st:st + nsec * 40])
    flags = 1  # bit0: embedded .text is final plaintext -> decrypt must skip decrypt_data8
    # Verbatim target header region. Must cover at least through the section
    # table; clamp to the actual target length so we never read past EOF.
    hdr_len = max(shdr, st + nsec * 40)
    hdr_len = min(hdr_len, len(T))
    hdr_bytes = bytes(T[:hdr_len])
    payload = (struct.pack('<IIII', nsec, simg, shdr, flags) + sectbl
               + struct.pack('<I', len(hdr_bytes)) + hdr_bytes)
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    return payload + struct.pack('<II', crc, len(payload)) + _TGT_HDR_MAGIC


# ----------------------------------------------------------------- pack
def pack_program(prof, S_fd, T, use_lz=False, do_imports=True, overlap=False):
    info = prof.info
    info3 = info[3]
    cdo = prof.compress_data_offset
    tgt = parse_target(T)
    # OVERLAP (native CrackProof design): reconstruct the FULL target program
    # [0x1000:tgt_image] via compressedInfo. The tail [info3:tgt_image] decompresses
    # over the shell at runtime (the shell's last step before OEP), so no image
    # growth and SizeOfImage == target image. Without overlap, the program is capped
    # at info3 (shell sits above) and the tail is dropped.
    prog_end = tgt['image_size'] if overlap else min(tgt['image_size'], info3)
    if (not overlap) and tgt['image_size'] > info3:
        print(f'  [!] WARNING: target image 0x{tgt["image_size"]:X} exceeds this '
              f'stub program capacity info3=0x{info3:X}; the top '
              f'0x{tgt["image_size"] - info3:X} bytes (sections above the cap) are '
              f'dropped -> re-unpacked PE will be incomplete. Use a larger stub.')

    # 1. decoded_image: template shell + target program region. Under overlap, T is
    #    written over the whole [0x1000:tgt_image] (incl. the shell VA range); `img`
    #    is only the compressedInfo SOURCE, the shell is emitted from raw_shell.
    img = bytearray(prof.decoded_image)
    img[0x1000:prog_end] = T[0x1000:prog_end]
    if tgt['image_size'] < info3:
        img[tgt['image_size']:info3] = b'\x00' * (info3 - tgt['image_size'])
    if do_imports:
        encrypt_target_imports(img, tgt)

    # 2. rebuild compressedInfo over the non-zero pages of [0x1000:prog_end].
    #    Group CONTIGUOUS non-zero pages into a single block (capped at MAX_BLK, below
    #    the decoder's 0x200000 size validation) instead of one record per 4KB page.
    #    Dense images (.NET assemblies) have ~1 record/page = thousands of records,
    #    which overflow a stub's compressedInfo table; grouping (like CrackProof's own
    #    multi-page blocks) keeps the record count low enough to fit any stub table.
    aes_ek = e.derive_aes_encrypt_keys(prof.decoded_image, prof.key_offsets[2])
    inv_tt = e.inverse_translate_table(prof.file_dec)
    lz_sym = None
    if use_lz:
        lz_sym = lz.parse_huffman(prof.decoded_image, prof.key_offsets[0])
    payload = bytearray()
    records = []
    MAX_BLK = 0x100000
    page = 0x1000
    while page < prog_end:
        if not any(img[page:min(page + 0x1000, prog_end)]):
            page += 0x1000
            continue  # zero page: the runtime image is zero-initialised already
        run_start = page
        while (page < prog_end and (page - run_start) < MAX_BLK
               and any(img[page:min(page + 0x1000, prog_end)])):
            page += 0x1000
        run_end = min(page, prog_end)
        chunk = bytes(img[run_start:run_end])
        if use_lz:
            blk, ssz = r.encode_block(chunk, aes_ek, prof.file_dec, inv_tt, lz_sym)
        else:
            blk = r.encode_block_nolz(chunk, aes_ek, prof.file_dec, inv_tt)
            ssz = len(chunk)
        while len(payload) % 4:
            payload.append(0)
        records.append((len(payload), ssz, run_start, len(chunk)))
        payload.extend(blk)

    # 3. metadata FIRST: target EP + 16 data directories.
    #    On Layout-B stubs the compressedInfo records overlap the metadata
    #    block's padding tail (e.g. amdaemon: meta=[info3+0x10:+0x2A0],
    #    compressedInfo@info3+0x270). Metadata must therefore be written BEFORE
    #    the records so the records win the overlap (mirrors repack_same_image);
    #    otherwise the metadata write clobbers the first records and the decoder
    #    mis-reads their s_size/d_size, triggering a bogus LZ decompress.
    raw_shell = bytearray(prof.raw_shell)
    if prof.meta_plain is not None:
        mbuf = bytearray(prof.meta_plain)
        w32(mbuf, prof.meta_ep_rel, tgt['ep'])
        # Data dirs are BLOCK-relative: +0x10 (Layout A, 144B; EP@+0x00) or
        # +0x20 (Layout B, 0x290B; EP@+0x10). meta_off is already info3+X.
        dirs_rel = 0x10 if prof.meta_size == 144 else 0x20
        if dirs_rel + 128 <= prof.meta_size:
            mbuf[dirs_rel:dirs_rel + 128] = tgt['dirs']
        enc5 = e.encrypt_data5_record(bytes(mbuf), prof.meta_off)
        raw_shell[prof.meta_off:prof.meta_off + prof.meta_size] = enc5
        e.encrypt_data4_at(raw_shell, prof.meta_off, prof.meta_size, prof.data4_va)

    # 4. compressedInfo records (Data4 outer / Data5 inner) + zero terminator +
    #    empty zeroList terminator, at the template's table address. Writing
    #    after metadata means the records overwrite any metadata padding tail.
    base = prof.compressed_info_addr
    table = records + [(0, 0, 0, 0), (0, 0, 0, 0)]  # cInfo terminator + empty zeroList
    end_addr = base + len(table) * 16
    if end_addr > prof.data4_va + prof.data4_sz:
        raise ValueError(f'compressedInfo table too large for template '
                         f'({len(records)} records); pick a roomier stub')
    for j, rec in enumerate(table):
        off = base + j * 16
        enc5 = e.encrypt_data5_record(struct.pack('<IIII', *rec), off)
        raw_shell[off:off + 16] = enc5
        e.encrypt_data4_at(raw_shell, off, 16, prof.data4_va)

    # 5. emit: header+info+Data2 (S's, with target section table) + payload + sections
    out = bytearray(S_fd[:cdo]) + bytes(payload)
    out[0x1000:0x1020] = e.encrypt_data1_info(info)
    shell_src = info[4] + 0x1000
    enc_shell = e.encrypt_data2_shell(
        raw_shell[info3:info3 + prof.decrypt_size], info, prof.decrypt_size)
    out[shell_src:shell_src + len(enc_shell)] = enc_shell

    # rewrite the packed PE section table to the target's sections + SizeOfImage,
    # keeping the stub entry point (loader runs the stub, not the target EP).
    same_layout = _section_layout_matches(S_fd, prof.pe, tgt)
    if same_layout:
        _rebuild_packed_header(out, S_fd, prof, tgt)
        r.relocate_sections(out, S_fd, prof.pe)   # template page block (validated)
    else:
        # Cross-layout: keep the DONOR's section table + data directories intact
        # so the Windows loader maps the stub exactly as it maps the donor and
        # resolves the stub's bootstrap imports. The stub then reconstructs the
        # target from the file-data layer (compressedInfo) and jumps to the target
        # OEP from the metadata. (Rewriting the header to the target's layout makes
        # the stub's import RVA unmapped -> the process won't start.)
        r.relocate_sections(out, S_fd, prof.pe)
        _make_sections_rwx(out, prof.pe)
    # EOF trailer: target section table + SKIP_D8 so decrypt rebuilds the final PE
    # header and skips decrypt_data8 (embedded .text is already final plaintext).
    out.extend(_build_target_hdr_trailer(T))
    return out, prog_end


def _make_sections_rwx(out, spe):
    """Make every section RWX. Under cross-layout packing the loader maps the
    DONOR's section table, so the target's regions inherit the donor's
    permissions (e.g. the target's .data lands inside the donor's RX .text). RWX
    lets the target read/write/execute anywhere, so it doesn't fault at the OEP.
    Section characteristics live past the header-checksummed area, so this is
    invisible to the stub's integrity check."""
    sopt = u16(out, spe + 20)
    st = spe + 24 + sopt
    nsec = u16(out, spe + 6)
    rwx = 0xE0000060  # EXECUTE|READ|WRITE | CNT_CODE | CNT_INITIALIZED_DATA
    for i in range(nsec):
        w32(out, st + i * 40 + 36, rwx)


def _section_layout_matches(S_fd, spe, tgt):
    """True when the template's packed section table already equals the target's
    (same count, VAs, VSizes) -- the common case where the target IS the stub's
    own program. Then the validated repack relocate can be reused."""
    sopt = u16(S_fd, spe + 20)
    if u16(S_fd, spe + 6) != tgt['nsec']:
        return False
    st = spe + 24 + sopt
    for i in range(tgt['nsec']):
        s = st + i * 40
        if u32(S_fd, s + 12) != tgt['sections'][i]['va']:
            return False
        if u32(S_fd, s + 8) != tgt['sections'][i]['vs']:
            return False
    return True


def _pack_relocate(out, prof, tgt, S_fd):
    """Give each TARGET section a placeholder raw page after the payload and set
    PtrRaw, so the packed file is a valid PE the loader can map. The section
    holding the stub entry point gets the donor bootstrap page so the stub can
    start. Works for arbitrary target layouts."""
    spe = prof.pe
    sopt = u16(S_fd, spe + 20)
    s_sectab = spe + 24 + sopt
    file_align = u32(S_fd, spe + 24 + 36)
    stub_ep = u32(S_fd, spe + 40)  # packed entry = stub bootstrap RVA

    # donor's own .text bootstrap page (first packed section raw page).
    boot_page = b'\x00' * 0x1000
    first_rp = u32(S_fd, s_sectab + 20)
    if first_rp and first_rp + 0x1000 <= len(S_fd):
        boot_page = bytes(S_fd[first_rp:first_rp + 0x1000])

    if len(out) % file_align:
        out.extend(b'\x00' * (file_align - (len(out) % file_align)))
    for i in range(tgt['nsec']):
        st = tgt['sections'][i]
        new_ptr = len(out)
        if st['va'] <= stub_ep < st['va'] + max(st['vs'], 0x1000):
            out.extend(boot_page)
        else:
            out.extend(b'\x00' * 0x1000)
        sh = s_sectab + i * 40
        w32(out, sh + 16, 0x1000)        # SizeOfRawData (placeholder page)
        w32(out, sh + 20, new_ptr)       # PointerToRawData
    return out


def _null_outofrange_dirs(out, prof, tgt):
    """Null the import / resource / base-reloc data directories in the packed PE
    header when they point outside the target's layout (cross-layout packing).
    The Windows loader would otherwise try to resolve the stub's bootstrap import
    table at the donor's high RVA, which no target section maps -> the process
    fails to start. These three directories are RESTORED from the shell anchor by
    the stub at run time, so nulling them in the file header is invisible to the
    stub AND does not affect the header checksum (the stub recomputes it after the
    restore). The stub self-resolves its own imports, so the loader does not need
    to."""
    pe = prof.pe
    img = tgt['image_size']
    for dir_off in (0x90, 0x98, 0xB0):   # import, resource, base-reloc
        rva = u32(out, pe + dir_off)
        if rva and rva >= img:
            w32(out, pe + dir_off, 0)
            w32(out, pe + dir_off + 4, 0)


def _rebuild_packed_header(out, S_fd, prof, tgt):
    """Make the packed PE header describe the TARGET's sections (correct layout +
    permissions for the target), keeping the stub entry point and a SizeOfImage
    large enough to also hold the shell. NOTE: the section count must stay equal
    to the donor's (the header checksum, used to derive the stage key, covers the
    section table); cross-layout import coverage is handled by _null_outofrange_dirs
    instead of by adding sections."""
    spe = prof.pe
    sopt = u16(S_fd, spe + 20)
    s_sectab = spe + 24 + sopt
    size_img = max(tgt['image_size'], prof.image_size)
    w32(out, spe + 80, size_img)
    for i in range(tgt['nsec']):
        st = tgt['sections'][i]
        dst = s_sectab + i * 40
        out[dst:dst + 8] = st['name']
        w32(out, dst + 8, st['vs'])
        w32(out, dst + 12, st['va'])
        w32(out, dst + 16, 0x1000)
        w32(out, dst + 20, 0)  # PtrRaw set by _pack_relocate
        w32(out, dst + 36, st['chars'])


# ----------------------------------------------------------------- verify
def verify(out, T, prof, prog_end, aes_dir, tag='pack'):
    """Verify the embedded program reconstructs correctly by re-parsing the packed
    file up to the file-decode loop and comparing the DECODED IMAGE (the program
    image right after the file loop, before .text d8-decrypt / import-name
    de-obfuscation, both of which are section-table-dependent post-processing).
    This is section-table-independent, so it is meaningful for both same-layout
    and cross-layout (donor section table) output. Diffs are allowed only inside
    the import directory (target import names are Data7-obfuscated in the decoded
    image, deobfuscated in the target)."""
    prof2 = r.unpack_template(bytearray(out))
    got = prof2.decoded_image
    tgt = parse_target(T)
    info3 = prof.info[3]
    # The OVERLAP tail [info3:image] is the target's zero-initialised BSS: no
    # compressedInfo record covers it, so the real decrypt zeros it (see
    # decrypt_crackproof). unpack_template leaves the shell's leftover bytes
    # there, so a got!=T mismatch where T is zero beyond info3 is NOT a pack
    # error -- skip it to mirror the real decrypt output.
    def _mismatch(k):
        if got[k] == T[k]:
            return False
        if k >= info3 and T[k] == 0:
            return False
        return True
    diffs = []
    i = 0x1000
    n = min(prog_end, len(got), len(T))
    while i < n:
        if _mismatch(i):
            j = i
            while j < n and _mismatch(j):
                j += 1
            diffs.append((i, j))
            i = j
        else:
            i += 1
    total = sum(b - a for a, b in diffs)
    # Allowed-diff region: the whole section that holds the import directory
    # (descriptors + ILT + IAT + name strings are Data7-obfuscated in the decoded
    # image but plaintext in the target, and span the entire import section for
    # import-heavy programs). Fall back to a window if no section matches.
    imp_lo = tgt['import_rva']
    imp_hi = imp_lo + max(tgt['import_size'], 0x2000) if imp_lo else 0
    for s in tgt['sections']:
        if imp_lo and s['va'] <= imp_lo < s['va'] + max(s['vs'], s['rawsz']):
            imp_lo, imp_hi = s['va'], s['va'] + max(s['vs'], s['rawsz'])
            break
    def in_imports(a, b):
        return imp_lo and imp_lo <= a and b <= imp_hi
    esc = [(a, b) for a, b in diffs if not in_imports(a, b)]
    print(f'  program-region diffs: {len(diffs)} ranges, {total} bytes; '
          f'{len(esc)} outside import section')
    for a, b in esc[:8]:
        print(f'    0x{a:X}..0x{b:X} (0x{b-a:X})')
    if not esc:
        print('  VERIFY OK: embedded program reconstructs to the target '
              '(import-dir diffs only)')
        return True
    return False


# ----------------------------------------------------------------- cli
def _do_pack(argv):
    ap = argparse.ArgumentParser(
        prog='encrypt_crackproof.py',
        description='CrackProof general packer (PE32+). Packs an unpacked PE32+ '
                    'into the bundled CrackProof stub. Output defaults to '
                    '<name>.packed<ext>.')
    ap.add_argument('target', help='unpacked PE32+ program to pack')
    ap.add_argument('profile', nargs='?', default=None,
                    help='stub profile (default: bundled stub_profile.bin)')
    ap.add_argument('-o', '--output', help='output path (default: <name>.packed<ext>)')
    ap.add_argument('--lz', action='store_true', help='real LZ compression (smaller output)')
    ap.add_argument('--no-overlap', action='store_true',
                    help='cap program at info3 (drop tail) instead of the native '
                         'overlap reconstruction; only for debugging')
    ap.add_argument('--no-verify', action='store_true', help='skip round-trip verification')
    ap.add_argument('--no-imports', action='store_true')
    ap.add_argument('--aes-dir', default=None, help='AES table dir (default: generate in code)')
    args = ap.parse_args(argv)
    aes_dir = Path(args.aes_dir) if args.aes_dir else None

    r.load_tables(aes_dir)
    prof_path = args.profile or BUNDLED_PROFILE
    if not Path(prof_path).exists():
        print(f'profile not found: {prof_path}\n'
              f'(extract one with: python encrypt_crackproof.py extract <packed_sample.exe> <profile>)')
        return 2
    blob = _load_profile(prof_path)
    prof = blob['prof']
    S_fd = bytearray(blob['file_data'])
    tgt_path = Path(args.target)
    T = bytearray(tgt_path.read_bytes())
    # output name = original name with ".packed" inserted before the extension.
    out_path = Path(args.output) if args.output else \
        tgt_path.with_name(tgt_path.stem + '.packed' + tgt_path.suffix)
    print(f'[*] packing {tgt_path.name} into stub '
          f'(profile={Path(prof_path).name}, info3=0x{prof.info[3]:X}) ...')
    out, prog_end = pack_program(prof, S_fd, T, use_lz=args.lz,
                                 do_imports=not args.no_imports,
                                 overlap=not args.no_overlap)
    out_path.write_bytes(out)
    print(f'[+] wrote {out_path.name} (0x{len(out):X} bytes)')
    if not args.no_verify:
        print('[*] verifying decrypt(pack) program region ...')
        ok = verify(out, T, prof, prog_end, aes_dir)
        return 0 if ok else 1
    return 0


def _do_extract(argv):
    ap = argparse.ArgumentParser(
        prog='encrypt_crackproof.py extract',
        description='Extract a reusable stub profile from a packed CrackProof sample.')
    ap.add_argument('template', help='packed CrackProof PE32+ sample')
    ap.add_argument('profile', help='output profile path')
    ap.add_argument('--aes-dir', default=None, help='AES table dir (default: generate in code)')
    args = ap.parse_args(argv)
    aes_dir = Path(args.aes_dir) if args.aes_dir else None
    r.load_tables(aes_dir)
    fd = bytearray(Path(args.template).read_bytes())
    print(f'[*] parsing template {Path(args.template).name} ...')
    prof = r.unpack_template(fd)
    blob = pickle.dumps({'file_data': bytes(fd), 'prof': prof})
    Path(args.profile).write_bytes(zlib.compress(blob, 9))
    print(f'[+] wrote profile {args.profile} '
          f'(info3=0x{prof.info[3]:X} image=0x{prof.image_size:X})')
    return 0


def main():
    argv = sys.argv[1:]
    # `extract` is an explicit subcommand; anything else is treated as a pack
    # target so the common case is just:  python encrypt_crackproof.py <unpacked.exe>
    if argv and argv[0] == 'extract':
        return _do_extract(argv[1:])
    return _do_pack(argv)


if __name__ == '__main__':
    raise SystemExit(main())
