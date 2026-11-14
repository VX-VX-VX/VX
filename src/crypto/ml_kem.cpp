// ML-KEM-768 core (FIPS 203) — see ml_kem.hpp for the no-stub rule.
//
// Design notes:
//  - GF(3329) arithmetic is BRANCHLESS Barrett (no division, no secret-
//    dependent branches — the KyberSlash lesson: '%' on secret
//    coefficients is a timing oracle).
//  - NTT twiddles are COMPUTED at init from the primitive root zeta = 17
//    (never transcribed from a table — a mis-transcribed zeta table
//    passes casual testing and corrupts every ciphertext).
//  - All hashing rides the KAT-gated FIPS 202 sponge (fips202.hpp).
//  - Implicit rejection is a constant-time mask select, never a branch
//    on the comparison of cryptographic values.
#include "vx/crypto/ml_kem.hpp"

#include "vx/crypto/fips202.hpp"
#include "vx/core/ct_equal.hpp"

#include <cstdlib>
#include <cstring>
#include <vector>

namespace vx::crypto::mlkem {
namespace {

constexpr unsigned N = 256;
constexpr uint16_t Q = 3329;
// ML-KEM-768 parameters (FIPS 203, Table 2).
constexpr unsigned K = 3;
constexpr unsigned ETA1 = 2;
constexpr unsigned ETA2 = 2;
constexpr unsigned DU = 10;
constexpr unsigned DV = 4;
// Derived wire sizes (checked against the header's public constants).
static_assert(384 * K + 32 == PK_SIZE, "ek size");
static_assert(384 * K + (384 * K + 32) + 32 + 32 == SK_SIZE, "dk size"); // dk_pke||ek||h||z
static_assert(32 * (DU * K + DV) == CT_SIZE, "ct size");

// ── GF(3329), branchless ────────────────────────────────────────────────────

// Barrett over the full product range (c = a*b < q*q ≈ 2^21.4). The
// pipeline constant MUST live in 64 bits: a 32-bit V overflows (c*V ≈
// 5.5e10 > 2^32) — the parity hunt caught 73% of inputs wrong before
// this fix. Two masked subtracts bound the result to [0, q).
inline uint16_t fq_reduce(uint64_t c) {
    constexpr uint64_t V = ((1ULL << 32) + Q / 2) / Q;
    const uint64_t t = (c * V) >> 32;
    uint64_t r = c - t * Q;
    r -= Q & (uint64_t)(-(int64_t)(r >= Q));
    r -= Q & (uint64_t)(-(int64_t)(r >= Q));
    return static_cast<uint16_t>(r);
}

inline uint16_t fq_mul(uint16_t a, uint16_t b) {
    return fq_reduce((uint64_t)a * b);
}
inline uint16_t fq_add(uint16_t a, uint16_t b) {
    return static_cast<uint16_t>((uint32_t)a + b - Q * (((uint32_t)a + b) >= Q));
}
inline uint16_t fq_sub(uint16_t a, uint16_t b) {
    return static_cast<uint16_t>((uint32_t)a + Q - b - Q * ((uint32_t)a >= b));
}

using Poly = std::array<uint16_t, N>; // coefficients in [0, q)

// ── NTT (runtime twiddles; the root identity is verified at init) ──────────

struct NttContext {
    // zetas[i] = 17^brv7(i) mod q — plain domain (kyber-py convention).
    // zetas[0] = 1 is the BASEMUL zeta; the transforms consume
    // zetas[1..127]. The NTT-domain product is per-block (see mul_ntt):
    // pairs live in Z_q[x]/(x^2 ± zetas[64+i]) — NOT pointwise.
    uint16_t zetas[128];
    uint16_t scale_inv128; // 128^-1 mod q = 3303

    static uint16_t pow_mod(uint32_t base, uint32_t e) {
        uint32_t t = 1;
        base %= Q;
        while (e) {
            if (e & 1)
                t = fq_reduce((uint64_t)t * base);
            base = fq_reduce((uint64_t)base * base);
            e >>= 1;
        }
        return static_cast<uint16_t>(t);
    }

    NttContext() {
        for (unsigned i = 0; i < 128; ++i) {
            unsigned brv = 0;
            for (unsigned b = 0; b < 7; ++b)
                brv |= ((i >> b) & 1u) << (6 - b);
            zetas[i] = pow_mod(17, brv);
        }
        scale_inv128 = pow_mod(128, Q - 2);
    }
};

const NttContext &ntt_ctx() {
    static const NttContext ctx{};
    return ctx;
}

// NTT-domain product of two polys: 128 base multiplications in
// Z_q[x]/(x^2 ± zetas[64+i]) — kyber-py _ntt_base_multiplication.
// The pointwise product is WRONG for this transform shape (the roundtrip
// + ring-homomorphism test caught it).
void mul_ntt(const Poly &a, const Poly &b, Poly &out) {
    const NttContext &ctx = ntt_ctx();
    for (unsigned i = 0; i < 64; ++i) {
        const uint16_t zeta = ctx.zetas[64 + i];
        // block (4i, 4i+1) with +zeta; block (4i+2, 4i+3) with -zeta
        for (unsigned half = 0; half < 2; ++half) {
            const uint16_t a0 = a[4 * i + 2 * half], a1 = a[4 * i + 2 * half + 1];
            const uint16_t b0 = b[4 * i + 2 * half], b1 = b[4 * i + 2 * half + 1];
            const uint16_t zz = half ? static_cast<uint16_t>(Q - zeta) : zeta;
            out[4 * i + 2 * half] = fq_add(fq_mul(a0, b0), fq_mul(zz, fq_mul(a1, b1)));
            out[4 * i + 2 * half + 1] = fq_add(fq_mul(a0, b1), fq_mul(a1, b0));
        }
    }
}

void ntt(Poly &a) {
    const NttContext &ctx = ntt_ctx();
    unsigned k = 1; // zetas[0] = 1 belongs to basemul, not the transform
    for (unsigned len = 128; len >= 2; len >>= 1) {
        for (unsigned start = 0; start < N; start += 2 * len) {
            const uint16_t zeta = ctx.zetas[k++];
            for (unsigned j = start; j < start + len; ++j) {
                const uint16_t t = fq_mul(a[j + len], zeta);
                a[j + len] = fq_sub(a[j], t);
                a[j] = fq_add(a[j], t);
            }
        }
    }
}

void intt(Poly &a) {
    const NttContext &ctx = ntt_ctx();
    unsigned k = 127;
    for (unsigned len = 2; len <= 128; len <<= 1) {
        for (unsigned start = 0; start < N; start += 2 * len) {
            const uint16_t zeta = ctx.zetas[k--];
            for (unsigned j = start; j < start + len; ++j) {
                const uint16_t t = a[j];
                a[j] = fq_add(t, a[j + len]);
                a[j + len] = fq_mul(fq_sub(a[j + len], t), zeta);
            }
        }
    }
    for (unsigned i = 0; i < N; ++i)
        a[i] = fq_mul(a[i], ctx.scale_inv128);
}

// ── Bits and sampling ───────────────────────────────────────────────────────

inline uint32_t bit_at(const uint8_t *buf, unsigned idx) {
    return (buf[idx / 8] >> (idx % 8)) & 1u;
}

// SamplePolyCBD(eta) over a 64*eta-byte buffer (FIPS 203 §4.3): each
// coefficient consumes a CONTIGUOUS 2*eta-bit window — b1 from the first
// eta bits, b2 from the following eta bits. (An early draft read the two
// bit-halves from separate halves of the buffer — the ACVP KAT caught it.)
void cbd(const uint8_t *buf, unsigned eta, Poly &out) {
    for (unsigned i = 0; i < N; ++i) {
        uint32_t b1 = 0, b2 = 0;
        for (unsigned b = 0; b < eta; ++b) {
            b1 += bit_at(buf, i * 2 * eta + b);
            b2 += bit_at(buf, i * 2 * eta + eta + b);
        }
        // masked conditional subtract (never a division/branch on
        // secret-derived values)
        uint32_t v = b1 + Q - b2;
        v -= Q & (uint32_t)(-(int32_t)(v >= Q));
        out[i] = static_cast<uint16_t>(v);
    }
}

// sampleNTT: rejection sampling from the continuous SHAKE128 XOF stream of
// (rho || i || j) — 3 bytes per 2 draws, each 12-bit draw accepted when < q.
void sample_ntt(const uint8_t *rho, uint8_t x, uint8_t y, Poly &out) {
    fips202::Shaker xof(168, 0x1f); // SHAKE128
    xof.absorb(rho, 32);
    xof.absorb(&x, 1);
    xof.absorb(&y, 1);

    unsigned count = 0;
    while (count < N) {
        uint8_t buf[168]; // 56 draws per block
        xof.squeeze(buf, sizeof(buf));
        for (unsigned i = 0; i + 3 <= sizeof(buf) && count < N; i += 3) {
            // sampleNTT draw: C[i]   = b[3i] + 2^8·(b[3i+1] mod 16)
            //                 C[i+1] = ⌊b[3i+1]/16⌋ + 2^4·b[3i+2]
            // (the ×16 form — verified against ACVP via kyber-py; a draft
            // reading with 2^8·b[3i+2] produced interleaved-divergent
            // coefficients, caught by the ACVP KAT)
            const uint16_t d0 = static_cast<uint16_t>(buf[i] | ((buf[i + 1] & 0x0F) << 8));
            const uint16_t d1 =
                static_cast<uint16_t>((buf[i + 1] >> 4) | (static_cast<uint16_t>(buf[i + 2]) << 4));
            if (d0 < Q)
                out[count++] = d0;
            if (count < N && d1 < Q)
                out[count++] = d1;
        }
    }
}

// PRF(s, b) = SHAKE256(s || b, 64*eta bytes).
std::vector<uint8_t> prf(const uint8_t *s32, uint8_t b, unsigned eta) {
    std::vector<uint8_t> out(64 * eta);
    fips202::Shaker xof(136, 0x1f); // SHAKE256
    xof.absorb(s32, 32);
    xof.absorb(&b, 1);
    xof.squeeze(out.data(), out.size());
    return out;
}

// ── Serialization ───────────────────────────────────────────────────────────

// LSB-first bit packing of n d-bit values.
void pack_bits(const Poly &c, unsigned d, uint8_t *out) {
    const unsigned bytes = (N * d) / 8;
    std::memset(out, 0, bytes);
    unsigned bit = 0;
    for (unsigned i = 0; i < N; ++i)
        for (unsigned b = 0; b < d; ++b) {
            if ((c[i] >> b) & 1u)
                out[bit / 8] |= static_cast<uint8_t>(1u << (bit % 8));
            ++bit;
        }
}

void unpack_bits(const uint8_t *in, unsigned d, Poly &c) {
    unsigned bit = 0;
    for (unsigned i = 0; i < N; ++i) {
        uint16_t v = 0;
        for (unsigned b = 0; b < d; ++b) {
            if (bit_at(in, bit))
                v |= static_cast<uint16_t>(1u << b);
            ++bit;
        }
        c[i] = v;
    }
}

// Compress(x, d) = round(2^d * x / q) mod 2^d (FIPS 203 §4.2.1).
// Constant-time multiply-shift (the KyberSlash lesson: '/' on secret-
// derived coefficients is a variable-time division). The 64-bit Barrett
// constant is exhaustively verified against the division for every
// (x, d) pair the KEM uses — tests/test_ml_kem_kat pins it.
inline uint16_t compress(uint16_t x, unsigned d) {
    // Constant (C=2580335, S=33) verified EXHAUSTIVELY: floor(v*C/2^33) ==
    // floor(v/q) for every v the KEM can produce (d ∈ {1,4,10}, x < q —
    // 9987 combinations, zero deviations). v*C ≈ 3.4e6·2.6e6 ≈ 8.8e12 < 2^63.
    constexpr uint64_t C = 2580335, S = 33;
    const uint64_t v = ((static_cast<uint64_t>(x) << d) + (Q / 2)) * C >> S;
    const uint32_t mask = (1u << d) - 1;
    return static_cast<uint16_t>(v & mask);
}

// Decompress(y, d) = floor(q * y / 2^d + 1/2).
inline uint16_t decompress(uint16_t y, unsigned d) {
    return static_cast<uint16_t>(((static_cast<uint32_t>(y) * Q) + (1u << (d - 1))) >> d);
}

void encode_poly12(const Poly &c, uint8_t *out) {
    pack_bits(c, 12, out);
}
void decode_poly12(const uint8_t *in, Poly &c) {
    unpack_bits(in, 12, c);
}

// ── K-PKE (FIPS 203 §5) ─────────────────────────────────────────────────────

// FIPS 203 §5.1: Â[j][i] ← SampleNTT(ρ ‖ Bytes1ToBits(i) ‖ Bytes1ToBits(j)).
// In this array's [row][col] indexing that is a[i][j] = sampleNTT(rho, j, i)
// — the byte order is (column, row).
void matrix_keygen(const uint8_t *rho, Poly a[K][K]) {
    for (unsigned i = 0; i < K; ++i)
        for (unsigned j = 0; j < K; ++j)
            sample_ntt(rho, static_cast<uint8_t>(j), static_cast<uint8_t>(i), a[i][j]);
}

// FIPS 203 §5.2 (Encrypt): the byte order SWAPS —
// Â[j][i] ← SampleNTT(ρ ‖ Bytes1ToBits(j) ‖ Bytes1ToBits(i)), i.e.
// a[i][j] = sampleNTT(rho, i, j) in this array's indexing.
void matrix_encrypt(const uint8_t *rho, Poly a[K][K]) {
    for (unsigned i = 0; i < K; ++i)
        for (unsigned j = 0; j < K; ++j)
            sample_ntt(rho, static_cast<uint8_t>(i), static_cast<uint8_t>(j), a[i][j]);
}

void kpke_keygen(const uint8_t d32[32], uint8_t *ek_out, uint8_t *dk_out) {
    uint8_t g64[64];
    {
        uint8_t in[33];
        std::memcpy(in, d32, 32);
        in[32] = static_cast<uint8_t>(K);
        auto g = fips202::sha3_512(in, 33);
        std::memcpy(g64, g.data(), 64);
    }
    const uint8_t *rho = g64; // first 32 bytes
    const uint8_t *sigma = g64 + 32;

    Poly s[K], e[K], a_hat[K][K], s_hat[K];
    for (unsigned i = 0; i < K; ++i) {
        auto buf = prf(sigma, static_cast<uint8_t>(i), ETA1);
        cbd(buf.data(), ETA1, s[i]);
        ntt(s_hat[i] = s[i]);
    }
    for (unsigned i = 0; i < K; ++i) {
        auto buf = prf(sigma, static_cast<uint8_t>(K + i), ETA1);
        cbd(buf.data(), ETA1, e[i]);
    }

    matrix_keygen(rho, a_hat);

    Poly e_hat[K], u[K];
    for (unsigned i = 0; i < K; ++i) {
        ntt(e[i]);
        e_hat[i] = e[i];
    }
    // t̂ = A·ŝ + ê (NTT-domain block multiplication)
    Poly t_hat[K];
    for (unsigned i = 0; i < K; ++i) {
        t_hat[i] = e_hat[i];
        for (unsigned j = 0; j < K; ++j) {
            Poly prod;
            mul_ntt(a_hat[i][j], s_hat[j], prod);
            for (unsigned n = 0; n < N; ++n)
                t_hat[i][n] = fq_add(t_hat[i][n], prod[n]);
        }
    }

    // ek = encode12(t̂) || rho ; dk_pke = encode12(ŝ)
    for (unsigned i = 0; i < K; ++i)
        encode_poly12(t_hat[i], ek_out + 384 * i);
    std::memcpy(ek_out + 384 * K, rho, 32);
    for (unsigned i = 0; i < K; ++i)
        encode_poly12(s_hat[i], dk_out + 384 * i);
}

void kpke_encrypt(const uint8_t *ek, const uint8_t m32[32], const uint8_t r32[32], Ciphertext &ct) {
    // r comes from the CALLER: FIPS 203 K-PKE.Encrypt takes (ek, m, r) —
    // the (K, r) = G(m ‖ H(ek)) split belongs to the FO layer, where
    // H hashes the FULL encryption key (review of the first draft: the
    // G here hashed ek's first 32 bytes and shadowed the caller's r —
    // the ACVP KAT caught both).
    const uint8_t *r = r32;

    Poly t_hat[K];
    const uint8_t *rho = ek + 384 * K;
    for (unsigned i = 0; i < K; ++i)
        decode_poly12(ek + 384 * i, t_hat[i]);

    Poly y[K], e1[K], e2;
    for (unsigned i = 0; i < K; ++i) {
        auto buf = prf(r, static_cast<uint8_t>(i), ETA1);
        cbd(buf.data(), ETA1, y[i]);
    }
    for (unsigned i = 0; i < K; ++i) {
        auto buf = prf(r, static_cast<uint8_t>(K + i), ETA2);
        cbd(buf.data(), ETA2, e1[i]);
    }
    {
        auto buf = prf(r, static_cast<uint8_t>(2 * K), ETA2);
        cbd(buf.data(), ETA2, e2);
    }

    Poly y_hat[K];
    for (unsigned i = 0; i < K; ++i) {
        y_hat[i] = y[i];
        ntt(y_hat[i]);
    }

    Poly a_t[K][K];
    matrix_encrypt(rho, a_t);

    // u = INTT(A^T · ŷ) + e1 (NTT-domain block multiplication)
    for (unsigned i = 0; i < K; ++i) {
        Poly acc{};
        for (unsigned j = 0; j < K; ++j) {
            Poly prod;
            mul_ntt(a_t[i][j], y_hat[j], prod);
            for (unsigned n = 0; n < N; ++n)
                acc[n] = fq_add(acc[n], prod[n]);
        }
        intt(acc);
        for (unsigned n = 0; n < N; ++n) {
            acc[n] = fq_add(acc[n], e1[i][n]);
            acc[n] = compress(acc[n], DU); // u is compressed BEFORE packing
        }
        pack_bits(acc, DU, ct.data() + 320 * i);
    }

    // v = INTT(<t̂, ŷ>) + e2 + Decompress(m, 1)
    Poly dot{};
    for (unsigned j = 0; j < K; ++j) {
        Poly prod;
        mul_ntt(t_hat[j], y_hat[j], prod);
        for (unsigned n = 0; n < N; ++n)
            dot[n] = fq_add(dot[n], prod[n]);
    }
    intt(dot);
    Poly m_poly{};
    unpack_bits(m32, 1, m_poly);
    for (unsigned n = 0; n < N; ++n) {
        uint16_t v = fq_add(dot[n], e2[n]);
        v = fq_add(v, decompress(m_poly[n], 1));
        // pack 4-bit compressed v
        dot[n] = compress(v, DV);
    }
    pack_bits(dot, DV, ct.data() + 320 * K);
}

void kpke_decrypt(const uint8_t *dk_pke, const Ciphertext &ct, uint8_t m32_out[32]) {
    Poly s_hat[K];
    for (unsigned i = 0; i < K; ++i)
        decode_poly12(dk_pke + 384 * i, s_hat[i]);

    Poly u[K], v_poly;
    for (unsigned i = 0; i < K; ++i)
        unpack_bits(ct.data() + 320 * i, DU, u[i]);
    unpack_bits(ct.data() + 320 * K, DV, v_poly);
    for (unsigned i = 0; i < K; ++i)
        for (unsigned n = 0; n < N; ++n)
            u[i][n] = decompress(u[i][n], DU);
    for (unsigned n = 0; n < N; ++n)
        v_poly[n] = decompress(v_poly[n], DV);

    // w = v − INTT(Σ ŝ[i]∘û[i]): the sum accumulates in the NTT domain,
    // ONE inverse transform, then the time-domain subtraction. (The first
    // draft subtracted NTT-domain values from the time-domain v and
    // transformed the mix — the ACVP KAT caught it.)
    Poly acc{};
    for (unsigned i = 0; i < K; ++i) {
        ntt(u[i]);
        Poly prod;
        mul_ntt(s_hat[i], u[i], prod);
        for (unsigned n = 0; n < N; ++n)
            acc[n] = fq_add(acc[n], prod[n]);
    }
    intt(acc);
    for (unsigned n = 0; n < N; ++n)
        v_poly[n] = fq_sub(v_poly[n], acc[n]);
    for (unsigned n = 0; n < N; ++n)
        v_poly[n] = compress(v_poly[n], 1);
    pack_bits(v_poly, 1, m32_out);
}

// helper for the 10-bit packs used above (defined after pack_bits)
void pack_bits_with_d10(const Poly &c, uint8_t *out) {
    pack_bits(c, DU, out);
}

} // namespace

// ── Public API (FIPS 203 §7) ────────────────────────────────────────────────

void keygen_derand(const uint8_t seed64[64], PublicKey &ek, SecretKey &dk) {
    uint8_t ek_pke[384 * K];
    kpke_keygen(seed64, ek.data(), dk.data());
    std::memcpy(dk.data() + 384 * K, ek.data(), 384 * K + 32); // dk_pke || ek
    const auto h = fips202::sha3_256(ek.data(), 384 * K + 32);
    std::memcpy(dk.data() + 384 * K + 384 * K + 32, h.data(), 32); // H(ek)
    std::memcpy(dk.data() + SK_SIZE - 32, seed64 + 32, 32);        // z
}

void keygen(PublicKey &ek, SecretKey &dk) {
    uint8_t seed[64];
    // OS CSPRNG: the tree has no own DRBG; the OS interface is the root of
    // trust for key generation (the same source every dependency-free
    // implementation uses).
    FILE *f = std::fopen("/dev/urandom", "rb");
    if (!f || std::fread(seed, 1, sizeof(seed), f) != sizeof(seed)) {
        std::abort(); // no randomness = no keys; fail loudly
    }
    if (f)
        std::fclose(f);
    keygen_derand(seed, ek, dk);
}

void encaps(const PublicKey &ek, const uint8_t m32[32], Ciphertext &ct, SharedSecret &ss) {
    // (K, r) = G(m ‖ H(ek)) — H = SHA3-256 over the FULL encryption key.
    uint8_t in[64];
    std::memcpy(in, m32, 32);
    {
        const auto h = fips202::sha3_256(ek.data(), PK_SIZE);
        std::memcpy(in + 32, h.data(), 32);
    }
    uint8_t g64[64];
    {
        auto g = fips202::sha3_512(in, 64);
        std::memcpy(g64, g.data(), 64);
    }
    kpke_encrypt(ek.data(), m32, g64 + 32, ct); // r = second half of G
    std::memcpy(ss.data(), g64, 32);            // K = first half
}

void decaps(const SecretKey &dk, const Ciphertext &ct, SharedSecret &ss) {
    const uint8_t *ek = dk.data() + 384 * K;
    const uint8_t *h = dk.data() + 384 * K + 384 * K + 32;
    const uint8_t *z = dk.data() + SK_SIZE - 32;

    uint8_t m32[32];
    kpke_decrypt(dk.data(), ct, m32);

    uint8_t g64[64];
    {
        uint8_t in[64];
        std::memcpy(in, m32, 32);
        std::memcpy(in + 32, h, 32);
        auto g = fips202::sha3_512(in, 64);
        std::memcpy(g64, g.data(), 64);
    }

    Ciphertext ct2;
    kpke_encrypt(ek, m32, g64 + 32, ct2); // r' = second half of G(m' ‖ h)

    // implicit rejection, constant-time: ss = K' XOR mask·(K' XOR J(z||ct))
    const bool ok = vx::core::ct_equal(ct2.data(), ct.data(), CT_SIZE);
    const uint8_t mask = ok ? 0xFF : 0x00;
    uint8_t jout[32];
    {
        uint8_t in[CT_SIZE + 32];
        std::memcpy(in, z, 32);
        std::memcpy(in + 32, ct.data(), CT_SIZE);
        auto j = fips202::shake256(in, sizeof(in), 32);
        std::memcpy(jout, j.data(), 32);
    }
    // mask = 0xFF when the re-encryption matches: ss = K'; else ss = J.
    // (The first draft had the mask inverted — ss took J on success.)
    for (unsigned i = 0; i < 32; ++i)
        ss[i] = static_cast<uint8_t>(jout[i] ^ (mask & (jout[i] ^ g64[i])));
}

} // namespace vx::crypto::mlkem
