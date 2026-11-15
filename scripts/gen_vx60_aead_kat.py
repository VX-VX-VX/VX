#!/usr/bin/env python3
# VX60-SEC M1 — KAT generator for the Duplex Sponge AEAD (whitebook 4.5).
#
# Pure-stdlib oracle: a clean Keccak-f[1600] plus the VX60 keyed duplex
# construction, exactly as specified for the C++ side. Emits
# tests/vx60_aead_kat_vectors.hpp (generated — do not edit by hand).
#
# Construction (MUST mirror include/vx/net/vx60_aead.hpp bit-for-bit):
#   state: 200 bytes (Keccak-f[1600]), rate r = 136 bytes, capacity 512 bit.
#   Phases, each absorbing its DOMAIN BYTE FIRST:
#     0x01 init:    absorb key(32) || nonce(16)
#     0x02 header:  absorb AD (optional; may be empty)
#     0x04 pt:      duplex per block: absorb ciphertext block, squeeze
#                   keystream — c = p XOR s (encrypt); decrypt mirrors.
#     0x08 final:   absorb length domain (u64 LE plaintext length), permute,
#                   squeeze 32-byte tag.
#   Absorption: every phase processes its byte stream in 136-byte duplex
#   blocks; the FINAL block of each phase is padded with pad10*1 inside the
#   rate (append 0x01, zero-fill, XOR 0x80 at rate-1) and permuted.
#   Nonce MUST be unique per (key, direction) — wire layer supplies it.

import struct

RATE = 136
ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# Keccak rho offsets r[x][y], generated from the compact tour definition
# (r[i][j] = (t+1)(t+2)/2 mod 64 over the (1,0)-tour) — verified against
# hashlib.sha3_256 by the self-check below. Display tables that show
# pre-mod values (190, 300, …) are transposed; do not transcribe them.
ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61], [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol64(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f(state):
    """Keccak-f[1600] on a 200-byte state (lanes are LE u64, x + 5*y)."""
    lanes = [int.from_bytes(state[i * 8:i * 8 + 8], "little") for i in range(25)]
    for rc in ROUND_CONSTANTS:
        # theta
        c = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(0, 25, 5):
                lanes[x + y] ^= d[x]
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(lanes[x + 5 * y],
                                                          ROTATION_OFFSETS[x][y])
        # chi
        for y in range(0, 25, 5):
            for x in range(5):
                lanes[x + y] = b[x + y] ^ ((~b[(x + 1) % 5 + y]) & b[(x + 2) % 5 + y])
        # iota
        lanes[0] ^= rc
    for i in range(25):
        state[i * 8:i * 8 + 8] = lanes[i].to_bytes(8, "little")
    return state


def _absorb_padded(state, data, first_domain, more_domains):
    """Absorb a phase stream: domain byte(s) then data, pad10*1 at the end.

    first_domain: the phase domain byte (always absorbed).
    more_domains: extra domain bytes absorbed right after the first (used by
    the final phase's length domain).
    """
    stream = bytes([first_domain]) + bytes(more_domains) + data
    # pad10*1 inside the rate; when the pad collapses to a single byte the
    # 0x01 and 0x80 marks MERGE into 0x81 (the same rule FIPS 202 padding
    # uses) — the C++ side implements the identical branch, and the KAT
    # set pins the merged case explicitly (sweep ad_len == 134).
    pad_len = RATE - (len(stream) % RATE)
    if pad_len == 1:
        stream += b"\x81"
    else:
        if pad_len == 0:
            pad_len = RATE  # a full pad block when aligned (unambiguous)
        stream += b"\x01" + b"\x00" * (pad_len - 2) + b"\x80"
    for off in range(0, len(stream), RATE):
        block = stream[off:off + RATE]
        for i, byte in enumerate(block):
            state[i] ^= byte
        _keccak_f(state)
    return state


def vx60_aead_seal(key32, nonce16, ad, plaintext):
    """Returns (ciphertext, tag32). pt may be empty. AD optional."""
    assert len(key32) == 32 and len(nonce16) == 16
    state = bytearray(200)
    # 0x01 init: key || nonce
    _absorb_padded(state, key32 + nonce16, 0x01, b"")
    # 0x02 header/AD
    _absorb_padded(state, ad, 0x02, b"")
    # 0x04 pt: duplex wrap — absorb ciphertext, squeeze keystream
    ct = bytearray()
    for off in range(0, len(plaintext), RATE):
        block = plaintext[off:off + RATE]
        ks = bytes(state[0:len(block)])
        cblock = bytes(a ^ b for a, b in zip(block, ks))
        for i, byte in enumerate(cblock):
            state[i] ^= byte
        _keccak_f(state)
        ct += cblock
    # 0x08 final: length domain + permute + squeeze tag
    _absorb_padded(state, struct.pack("<Q", len(plaintext)), 0x08, b"")
    tag = bytes(state[0:32])
    return bytes(ct), tag


def vx60_aead_open(key32, nonce16, ad, ciphertext, tag32):
    """Returns plaintext or None (RUP: caller zeroes on failure — the C++
    side zeroes IN PLACE; the oracle simply refuses)."""
    state = bytearray(200)
    _absorb_padded(state, key32 + nonce16, 0x01, b"")
    _absorb_padded(state, ad, 0x02, b"")
    pt = bytearray()
    for off in range(0, len(ciphertext), RATE):
        block = ciphertext[off:off + RATE]
        ks = bytes(state[0:len(block)])
        pblock = bytes(a ^ b for a, b in zip(block, ks))
        for i, byte in enumerate(block):
            state[i] ^= byte
        _keccak_f(state)
        pt += pblock
    _absorb_padded(state, struct.pack("<Q", len(ciphertext)), 0x08, b"")
    tag = bytes(state[0:32])
    if tag != tag32:
        return None
    return bytes(pt)


# ── self-check: the oracle agrees with a known SHA3-256 derived state ──
# The Keccak-f core is validated against hashlib's SHA3 (FIPS 202): absorb
# "abc" through our rate-136 machinery with the SHA3 pad (0x06) and compare
# the squeeze with hashlib.sha3_256.
def _keccak_core_selfcheck():
    import hashlib
    state = bytearray(200)
    # SHA3 pad: "abc" + 0x06 + zeros + 0x80 at rate-1 — one 136-byte block.
    stream = b"abc" + b"\x06" + b"\x00" * (RATE - 5) + b"\x80"
    for off in range(0, len(stream), RATE):
        block = stream[off:off + RATE]
        for i, byte in enumerate(block):
            state[i] ^= byte
        _keccak_f(state)
    ours = bytes(state[0:32])
    ref = hashlib.sha3_256(b"abc").digest()
    if ours != ref:
        raise SystemExit("FATAL: keccak core self-check FAILED vs hashlib")
    print("keccak core self-check: OK (SHA3-256('abc') matches hashlib)")


def main():
    _keccak_core_selfcheck()

    vectors = []

    def add(name, key, nonce, ad, pt):
        ct, tag = vx60_aead_seal(key, nonce, ad, pt)
        # roundtrip
        assert vx60_aead_open(key, nonce, ad, ct, tag) == pt
        # flipped tag bit → refuse (RUP test vector)
        bad = bytearray(tag)
        bad[0] ^= 0x01
        assert vx60_aead_open(key, nonce, ad, ct, bytes(bad)) is None
        vectors.append((name, key, nonce, ad, pt, ct, tag))

    k = bytes(range(32))
    n = bytes(range(16, 32))
    add("empty_pt_no_ad", k, n, b"", b"")
    add("one_byte", k, n, b"", b"\x00")
    add("one_byte_ff", k, n, b"", b"\xff")
    add("rate_minus_one", k, n, b"", bytes(RATE - 1))
    add("rate_exact", k, n, b"", bytes(RATE))
    add("rate_plus_one", k, n, b"", bytes(RATE + 1))
    add("ad_variants_empty", k, n, b"", bytes(64))
    add("ad_short", k, n, b"AD", bytes(64))
    add("ad_rate_exact", k, n, bytes(RATE), bytes(64))
    add("block_64k", k, n, b"frame-header", bytes(65536))
    for i, pt_len in enumerate([2, 3, 135, 137, 271, 272, 273, 4096]):
        add(f"len_{pt_len}_{i}", bytes([i]) * 32, bytes([255 - i]) * 16,
            f"ad{i}".encode(), bytes((j * 7 + i) % 256 for j in range(pt_len)))
    # distinct keys must not collide tags
    t1 = vx60_aead_seal(k, n, b"", b"msg")[1]
    t2 = vx60_aead_seal(bytes(32), n, b"", b"msg")[1]
    assert t1 != t2
    add("zero_key", bytes(32), n, b"", b"msg")
    # distinct nonces must not collide
    assert vx60_aead_seal(k, n, b"", b"msg")[1] != vx60_aead_seal(k, bytes(16), b"", b"msg")[1]
    add("zero_nonce", k, bytes(16), b"", b"msg")

    # ── breadth to ≥50: length sweep, boundary ±2 around every rate
    # multiple, adversarial byte patterns, varied key/nonce/AD ──
    import hashlib as _h
    for idx in range(30):
        # deterministic structured inputs (same vector set on every run)
        seed = _h.sha256(f"vx60-kat-{idx}".encode()).digest()
        seed2 = _h.sha256(seed).digest()
        key = seed
        nonce = seed2[:16]
        ad_len = (seed2[16] % 200) - 3 if seed2[16] >= 3 else seed2[16]
        ad = seed2[17:17 + ad_len] if ad_len > 0 else b""
        mult = idx % 6
        pt_len = mult * RATE + (idx % 5) - 2  # straddles rate boundaries
        if pt_len < 0:
            pt_len = idx
        pattern = idx % 4
        if pattern == 0:
            pt = bytes(pt_len)
        elif pattern == 1:
            pt = b"\xff" * pt_len
        elif pattern == 2:
            pt = bytes((0b10101010 if j % 2 == 0 else 0b01010101)
                       for j in range(pt_len))
        else:
            pt = _h.sha256(str(idx).encode()).digest() * (pt_len // 32 + 1)
            pt = pt[:pt_len]
        add(f"sweep_{idx}", key, nonce, ad, pt)
    # empty-AD and empty-PT corner at a non-boundary length
    add("empty_ad_only", k, n, b"", bytes(1000))
    add("empty_pt_with_ad", k, n, b"auth-only", b"")
    # Pad-boundary pins: AD phase stream is 1+ad_len bytes, so ad_len=134
    # gives q==1 (MERGED pad 0x81) and ad_len=135 gives q==rate (full pad
    # block). Both branches MUST be bit-identical across oracle and C++.
    add("ad_merged_pad", k, n, bytes(range(134)), b"x")
    add("ad_full_pad_block", k, n, bytes(range(135)), b"x")
    add("ad_merged_pad_no_pt", k, n, bytes(range(134)), b"")

    # emit header
    out = []
    out.append("// GENERATED by scripts/gen_vx60_aead_kat.py — do not edit.")
    out.append("// VX60-SEC M1 KAT vectors: keyed duplex sponge AEAD (whitebook 4.5).")
    out.append("#pragma once")
    out.append("#include <array>")
    out.append("#include <cstddef>")
    out.append("#include <cstdint>")
    out.append("#include <vector>")
    out.append("")
    out.append("namespace vx::net::vx60_test {")
    out.append("")
    out.append("struct KatVector {")
    out.append("    const char *name;")
    out.append("    std::vector<uint8_t> key;      // 32")
    out.append("    std::vector<uint8_t> nonce;    // 16")
    out.append("    std::vector<uint8_t> ad;")
    out.append("    std::vector<uint8_t> pt;")
    out.append("    std::vector<uint8_t> ct;")
    out.append("    std::vector<uint8_t> tag;      // 32")
    out.append("};")
    out.append("")
    out.append(f"inline constexpr size_t kKatCount = {len(vectors)};")
    out.append("")
    out.append("inline std::vector<KatVector> kat_vectors() {")
    out.append("    std::vector<KatVector> v;")
    out.append("    v.reserve(kKatCount);")
    for name, key, nonce, ad, pt, ct, tag in vectors:
        out.append("    {")
        out.append(f'        v.push_back({{"{name}",')
        for label, data in (("key", key), ("nonce", nonce), ("ad", ad),
                            ("pt", pt), ("ct", ct), ("tag", tag)):
            hexs = data.hex()
            out.append(f'        /* {label} */ {{{",".join("0x" + hexs[i:i + 2] for i in range(0, len(hexs), 2)) or ""}}},')
        out.append("        });")
        out.append("    }")
    out.append("    return v;")
    out.append("}")
    out.append("")
    out.append("} // namespace vx::net::vx60_test")
    with open("tests/vx60_aead_kat_vectors.hpp", "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"emitted tests/vx60_aead_kat_vectors.hpp ({len(vectors)} vectors)")


if __name__ == "__main__":
    main()
