// FIPS 205 — SLH-DSA-SHAKE-128s implementation (Phase B of the 0.2.x plan).
//
// Verbatim from the standard: every algorithm number cited below refers to
// FIPS 205 (August 13, 2024). The gate is bit-for-bit reproduction of the
// ACVP-Server SHAKE-128s vectors (tests/test_slh_dsa_acvp.cpp).
//
// Parameters (Table 2, SLH-DSA-SHAKE-128s):
//   n=16, h=63, d=7, h'=9, a=12, k=14, w=16, len=35, m=30.
// All Merkle tree nodes are n bytes; H_msg yields m=30 bytes.

#include "vx/crypto/slh_dsa.hpp"

#include "vx/crypto/fips202.hpp"

#include <cstring>
#include <span>
#include <type_traits>

namespace vx::crypto::slh {
namespace {

using fips202::Shaker;

// Accept both std::array-like byte buffers and raw bounded arrays (e.g.
// Adrs::b) as absorb spans.
template <typename T> auto span_of(const T &t) noexcept {
    if constexpr (std::is_bounded_array_v<T>) {
        return std::span<const uint8_t, std::extent_v<T>>(t);
    } else {
        return t;
    }
}

// SHAKE256 one-shot over disjoint byte spans, no heap allocation in the
// hot path. All FIPS 205 primitives are SHAKE256 with an explicit output
// length, so the sponge is reused directly.
template <typename... Spans>
void shake256_out(uint8_t *out, size_t out_len, const Spans &...spans) noexcept {
    Shaker sh(136, 0x1f);
    (sh.absorb(span_of(spans).data(), span_of(spans).size()), ...);
    sh.squeeze(out, out_len);
}

// Algorithm 2 toInt: big-endian byte string -> integer.
uint64_t to_int(const uint8_t *x, size_t n) noexcept {
    uint64_t total = 0;
    for (size_t i = 0; i < n; ++i)
        total = (total << 8) | x[i];
    return total;
}

// Algorithm 3 toByte: integer -> big-endian byte string.
void to_byte(uint8_t *out, uint64_t x, size_t n) noexcept {
    for (size_t i = 0; i < n; ++i)
        out[n - 1 - i] = static_cast<uint8_t>(x >> (8 * i));
}

// Algorithm 4 base_2b: first out_len*b bits of X as base-2^b integers.
// The output is uint32_t: FORS uses b = a = 12, so values reach 4095 and do
// NOT fit in a byte — a uint8_t out array would silently truncate them.
void base_2b(uint32_t *out, const uint8_t *x, unsigned b, size_t out_len) noexcept {
    unsigned total = 0, bits = 0;
    size_t in = 0;
    for (size_t out_i = 0; out_i < out_len; ++out_i) {
        while (bits < b) {
            total = (total << 8) + x[in++];
            bits += 8;
        }
        bits -= b;
        out[out_i] = (total >> bits) & ((1u << b) - 1);
    }
}

// ADRS layout (FIPS 205 §7.2, 32 bytes):
//   layer[0:4] | tree[4:16] | type[16:20] | keyPair[20:24] |
//   chain/treeHeight[24:28] | treeIndex/hash[28:32].
constexpr size_t kLayer = 0, kTree = 4, kType = 16, kKp = 20, kChain = 24, kHash = 28;
constexpr size_t kTreeBytes = 12;

void put_be(uint8_t *b, size_t off, uint64_t v, size_t len) noexcept {
    // toByte(x, n) takes the LOW 8n bits of x big-endian; for n > 8 the
    // bytes beyond the 64-bit value are zero. Shifting by 8*i >= 64 would
    // be UB (SAN lane caught it on the 12-byte tree address), so clamp.
    for (size_t i = 0; i < len; ++i) {
        const unsigned sh = 8u * static_cast<unsigned>(i);
        b[off + len - 1 - i] = static_cast<uint8_t>(sh < 64 ? (v >> sh) : 0);
    }
}

uint64_t get_be(const uint8_t *b, size_t off, size_t len) noexcept {
    uint64_t v = 0;
    for (size_t i = 0; i < len; ++i)
        v = (v << 8) | b[off + i];
    return v;
}

// Load an n-byte std::array from a raw pointer (aggregate-init from a
// pointer is not valid C++).
bytes16 load16(const uint8_t *p) noexcept {
    bytes16 out{};
    std::memcpy(out.data(), p, N);
    return out;
}

} // namespace

// ── Adrs ────────────────────────────────────────────────────────────────────

void Adrs::set_layer(uint32_t v) noexcept {
    put_be(b, kLayer, v, 4);
}
void Adrs::set_tree(uint64_t v) noexcept {
    put_be(b, kTree, v, kTreeBytes);
}
void Adrs::set_type(uint32_t v) noexcept {
    put_be(b, kType, v, 4);
}
void Adrs::set_kp(uint32_t v) noexcept {
    put_be(b, kKp, v, 4);
}
void Adrs::set_chain(uint32_t v) noexcept {
    put_be(b, kChain, v, 4);
}
void Adrs::set_hash(uint32_t v) noexcept {
    put_be(b, kHash, v, 4);
}
uint64_t Adrs::tree() const noexcept {
    return get_be(b, kTree, kTreeBytes);
}
uint32_t Adrs::layer() const noexcept {
    return static_cast<uint32_t>(get_be(b, kLayer, 4));
}
uint32_t Adrs::kp() const noexcept {
    return static_cast<uint32_t>(get_be(b, kKp, 4));
}
uint32_t Adrs::chain() const noexcept {
    return static_cast<uint32_t>(get_be(b, kChain, 4));
}
uint32_t Adrs::hash() const noexcept {
    return static_cast<uint32_t>(get_be(b, kHash, 4));
}

void Adrs::set_type_and_clear(uint32_t t) noexcept {
    set_type(t);
    set_kp(0);
    set_chain(0);
    set_hash(0);
}
void Adrs::set_type_keep(uint32_t t) noexcept {
    set_type(t);
}

// ── Primitives (FIPS 205 §11.1) ─────────────────────────────────────────────

bytes16 chain_hash(const bytes16 &pk_seed, const Adrs &adrs, const bytes16 &tmp) noexcept {
    // F = SHAKE256(PK.seed || ADRS || M1, 8n)
    bytes16 out{};
    shake256_out(out.data(), N, pk_seed, adrs.b, tmp);
    return out;
}

bytes16 h_hash(const bytes16 &pk_seed, const Adrs &adrs, const bytes16 &m1,
               const bytes16 &m2) noexcept {
    // H = SHAKE256(PK.seed || ADRS || M1 || M2, 8n)
    bytes16 out{};
    shake256_out(out.data(), N, pk_seed, adrs.b, m1, m2);
    return out;
}

bytes16 t_hash(const bytes16 &pk_seed, const Adrs &adrs, const uint8_t *parts, size_t n) noexcept {
    // T_l = SHAKE256(PK.seed || ADRS || M_l, 8n)
    bytes16 out{};
    shake256_out(out.data(), N, pk_seed, adrs.b, std::span(parts, n));
    return out;
}

bytes16 prf(const bytes16 &pk_seed, const bytes16 &sk_seed, const Adrs &adrs) noexcept {
    // PRF = SHAKE256(PK.seed || ADRS || SK.seed, 8n)
    bytes16 out{};
    shake256_out(out.data(), N, pk_seed, adrs.b, sk_seed);
    return out;
}

// Absorb M' = toByte(0,1) || toByte(len(ctx),1) || ctx || M into a running
// SHAKE256 sponge — never materialized (messages may be arbitrarily long).
// addrnd is NOT part of M'; it is the opt_rand input of PRF_msg. Returns
// false when ctx_len > 255 (the one-byte length field cannot encode it).
bool absorb_m_prime(Shaker &sh, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                    size_t ctx_len) noexcept {
    if (ctx_len > 255)
        return false;
    const uint8_t hdr[2] = {0, static_cast<uint8_t>(ctx_len)};
    sh.absorb(hdr, 2);
    if (ctx_len)
        sh.absorb(ctx, ctx_len);
    if (msg_len)
        sh.absorb(msg, msg_len);
    return true;
}

bool prf_msg(const bytes16 &sk_prf, const bytes16 &opt_rand, const uint8_t *msg, size_t msg_len,
             const uint8_t *ctx, size_t ctx_len, bytes16 &out) noexcept {
    // PRF_msg = SHAKE256(SK.prf || opt_rand || M', 8n)
    Shaker sh(136, 0x1f);
    sh.absorb(sk_prf.data(), N);
    sh.absorb(opt_rand.data(), N);
    if (!absorb_m_prime(sh, msg, msg_len, ctx, ctx_len))
        return false;
    sh.squeeze(out.data(), N);
    return true;
}

bool msg_hash(const bytes16 &r, const bytes16 &pk_seed, const bytes16 &pk_root, const uint8_t *msg,
              size_t msg_len, const uint8_t *ctx, size_t ctx_len, bytes32 &out) noexcept {
    // H_msg = SHAKE256(R || PK.seed || PK.root || M', 8m)
    Shaker sh(136, 0x1f);
    sh.absorb(r.data(), N);
    sh.absorb(pk_seed.data(), N);
    sh.absorb(pk_root.data(), N);
    if (!absorb_m_prime(sh, msg, msg_len, ctx, ctx_len))
        return false;
    sh.squeeze(out.data(), M);
    return true;
}

// Internal primitives (FIPS 205 §9.1): the internal slh_sign_internal /
// slh_verify_internal take M' as-is — the M' = toByte(0,1) ||
// toByte(len(ctx),1) || ctx || M wrapper belongs to the external slh_sign /
// slh_verify only (FIPS 205 §11.1). The ACVP internalProjection sigVer
// vectors are internal-interface: their message field IS M'.
void prf_msg_internal(const bytes16 &sk_prf, const bytes16 &opt_rand, const uint8_t *m_prime,
                      size_t m_prime_len, bytes16 &out) noexcept {
    // PRF_msg = SHAKE256(SK.prf || opt_rand || M', 8n)
    Shaker sh(136, 0x1f);
    sh.absorb(sk_prf.data(), N);
    sh.absorb(opt_rand.data(), N);
    if (m_prime_len)
        sh.absorb(m_prime, m_prime_len);
    sh.squeeze(out.data(), N);
}

void msg_hash_internal(const bytes16 &r, const bytes16 &pk_seed, const bytes16 &pk_root,
                       const uint8_t *m_prime, size_t m_prime_len, bytes32 &out) noexcept {
    // H_msg = SHAKE256(R || PK.seed || PK.root || M', 8m)
    Shaker sh(136, 0x1f);
    sh.absorb(r.data(), N);
    sh.absorb(pk_seed.data(), N);
    sh.absorb(pk_root.data(), N);
    if (m_prime_len)
        sh.absorb(m_prime, m_prime_len);
    sh.squeeze(out.data(), M);
}

// ── WOTS+ (FIPS 205 §6.1, Algorithms 5–8) ───────────────────────────────────

void wots_base(const uint8_t digest[32], uint8_t out_b[LEN]) noexcept {
    // LOGW = 4: values 0..15 fit in a byte, but base_2b is uint32_t —
    // widen a local buffer and copy back.
    uint32_t wide[LEN1];
    base_2b(wide, digest, LOGW, LEN1);
    for (unsigned i = 0; i < LEN1; ++i)
        out_b[i] = static_cast<uint8_t>(wide[i]);
    // Checksum (Algorithm 7 lines 3-6): sum of (w-1 - digit) over len_1
    // digits, then 4-bit left shift (lgw=4, len_2=3) and base-2^w split.
    uint32_t csum = 0;
    for (unsigned i = 0; i < LEN1; ++i)
        csum += W - 1 - out_b[i];
    csum <<= 4;
    uint8_t csum_bytes[2];
    to_byte(csum_bytes, csum, 2);
    uint32_t wide2[LEN2];
    base_2b(wide2, csum_bytes, LOGW, LEN2);
    for (unsigned i = 0; i < LEN2; ++i)
        out_b[LEN1 + i] = static_cast<uint8_t>(wide2[i]);
}

bytes16 wots_chain(const bytes16 &pk_seed, const Adrs &adrs, const bytes16 &start,
                   unsigned start_idx, unsigned steps) noexcept {
    // Algorithm 4 chain(X, i, s, PK.seed, ADRS): the hash address starts at
    // `start_idx` (i) and increments — F is called with hash addresses
    // start_idx .. start_idx + steps - 1. A fresh wots_chain from the secret
    // value passes start_idx = 0; a continuation from a signature element
    // passes start_idx = b[i] (Algorithm 8).
    bytes16 tmp = start;
    Adrs a = adrs;
    for (unsigned i = 0; i < steps; ++i) {
        a.set_hash(start_idx + i);
        tmp = chain_hash(pk_seed, a, tmp);
    }
    return tmp;
}

void wots_pkgen(const bytes16 &pk_seed, const bytes16 &sk_seed, Adrs sk_adrs,
                bytes16 pk_out[LEN]) noexcept {
    // Algorithm 6: skADRS = copy of ADRS with type WOTS_PRF and the keyPair
    // address RESTORED (setTypeAndClear zeroes it — Algorithm 6 line 3);
    // the PRF is recomputed PER CHAIN with skADRS.setChainAddress(i)
    // (Algorithm 6 lines 5-6); pk[i] = chain(sk_i, 0, w-1, ADRS_i) using the
    // caller's ADRS verbatim (lines 7-8); pk = T_len over wotspkADRS with
    // the keyPair address restored (Algorithm 6 line 12).
    Adrs sk_adrs_prf = sk_adrs;
    sk_adrs_prf.set_type_and_clear(ADRS_WOTS_PRF);
    sk_adrs_prf.set_kp(sk_adrs.kp());
    Adrs a = sk_adrs;
    for (unsigned i = 0; i < LEN; ++i) {
        sk_adrs_prf.set_chain(i);
        const bytes16 sk = prf(pk_seed, sk_seed, sk_adrs_prf);
        a.set_chain(i);
        a.set_hash(0);
        pk_out[i] = wots_chain(pk_seed, a, sk, 0, W - 1);
    }
    a.set_type_and_clear(ADRS_WOTS_PK);
    a.set_kp(sk_adrs.kp());
    const bytes16 pk = t_hash(pk_seed, a, reinterpret_cast<const uint8_t *>(pk_out), LEN * N);
    std::memcpy(pk_out[0].data(), pk.data(), N);
}

void wots_sign(const bytes16 &pk_seed, const bytes16 &sk_seed, const Adrs &sk_adrs,
               const uint8_t digest[32], bytes16 sig_out[LEN]) noexcept {
    // Algorithm 7: skADRS (WOTS_PRF, keyPair restored) is recomputed PER
    // CHAIN with skADRS.setChainAddress(i) (Algorithm 7 lines 12-13);
    // sig[i] = chain(sk_i, 0, b[i], ADRS_i) using the caller's ADRS verbatim.
    uint8_t b[LEN];
    wots_base(digest, b);
    Adrs sk_adrs_prf = sk_adrs;
    sk_adrs_prf.set_type_and_clear(ADRS_WOTS_PRF);
    sk_adrs_prf.set_kp(sk_adrs.kp());
    Adrs a = sk_adrs;
    for (unsigned i = 0; i < LEN; ++i) {
        sk_adrs_prf.set_chain(i);
        const bytes16 sk = prf(pk_seed, sk_seed, sk_adrs_prf);
        a.set_chain(i);
        a.set_hash(0);
        sig_out[i] = wots_chain(pk_seed, a, sk, 0, b[i]);
    }
}

void wots_pk_from_sig(const bytes16 &pk_seed, const Adrs &adrs, const uint8_t digest[32],
                      const bytes16 sig[LEN], bytes16 pk_out[LEN]) noexcept {
    // Algorithm 8: tmp[i] = chain(sig[i], b[i], w-1-b[i], ADRS_i);
    // pk = T_len(PK.seed, pkADRS, tmp[0..len)).
    uint8_t b[LEN];
    wots_base(digest, b);
    Adrs a = adrs;
    for (unsigned i = 0; i < LEN; ++i) {
        a.set_chain(i);
        a.set_hash(0);
        pk_out[i] = wots_chain(pk_seed, a, sig[i], b[i], W - 1 - b[i]);
    }
    a.set_type_and_clear(ADRS_WOTS_PK);
    a.set_kp(adrs.kp());
    const bytes16 pk = t_hash(pk_seed, a, reinterpret_cast<const uint8_t *>(pk_out), LEN * N);
    std::memcpy(pk_out[0].data(), pk.data(), N);
}

// ── XMSS (FIPS 205 §6.2, Algorithms 9–11) ───────────────────────────────────

bytes16 xmss_node(const bytes16 &pk_seed, const bytes16 &sk_seed, uint64_t tree_idx,
                  unsigned node_idx, unsigned height, Adrs adrs) noexcept {
    // Algorithm 9: leaf = wots_pkGen; internal = H(l || r) with TREE type.
    if (height == 0) {
        adrs.set_type_and_clear(ADRS_WOTS_HASH);
        adrs.set_kp(static_cast<uint32_t>(node_idx));
        bytes16 pk[LEN];
        wots_pkgen(pk_seed, sk_seed, adrs, pk);
        return pk[0];
    }
    const bytes16 lnode = xmss_node(pk_seed, sk_seed, tree_idx, node_idx * 2, height - 1, adrs);
    const bytes16 rnode = xmss_node(pk_seed, sk_seed, tree_idx, node_idx * 2 + 1, height - 1, adrs);
    adrs.set_type_and_clear(ADRS_TREE);
    adrs.set_tree_height(height);
    adrs.set_tree_index(node_idx);
    return h_hash(pk_seed, adrs, lnode, rnode);
}

// XMSS signature: (len + h')*n bytes. SIG_HT is d such blocks.
void xmss_sign(const bytes16 &pk_seed, const bytes16 &sk_seed, uint32_t idx, const bytes16 &msg,
               const Adrs &adrs, uint8_t *sig_out) noexcept {
    // Algorithm 10: AUTH[j] = node(k, j) with k = floor(idx/2^j) ^ 1;
    // then WOTS+ sig with keyPairAddress = idx.
    Adrs a = adrs;
    a.set_type_and_clear(ADRS_TREE);
    for (unsigned j = 0; j < HP; ++j) {
        const uint32_t k = (idx >> j) ^ 1;
        const bytes16 auth = xmss_node(pk_seed, sk_seed, a.tree(), k, j, a);
        std::memcpy(sig_out + (LEN + j) * N, auth.data(), N);
    }
    a.set_type_and_clear(ADRS_WOTS_HASH);
    a.set_kp(idx);
    bytes16 wots_sig[LEN];
    wots_sign(pk_seed, sk_seed, a, msg.data(), wots_sig);
    std::memcpy(sig_out, reinterpret_cast<const uint8_t *>(wots_sig), LEN * N);
}

bytes16 xmss_pk_from_sig(uint32_t idx, const uint8_t *sig, const bytes16 &msg,
                         const bytes16 &pk_seed, Adrs adrs) noexcept {
    // Algorithm 11: root = wots_pkFromSig; then step up the tree using AUTH.
    Adrs a = adrs;
    a.set_type_and_clear(ADRS_WOTS_HASH);
    a.set_kp(idx);
    // wots_pk_from_sig writes all LEN chain results into pk_out before
    // overwriting pk_out[0] with the compressed key — the buffer must be
    // LEN bytes16, not the 2-slot node pair (a 528-byte stack smash).
    bytes16 tmp[LEN];
    wots_pk_from_sig(pk_seed, a, msg.data(), reinterpret_cast<const bytes16 *>(sig), tmp);
    const uint8_t *auth = sig + LEN * N;
    bytes16 node[2];
    node[0] = tmp[0];
    for (unsigned k = 0; k < HP; ++k) {
        a.set_type_and_clear(ADRS_TREE);
        a.set_tree_height(k + 1);
        if ((idx >> k) & 1u) {
            a.set_tree_index((idx >> (k + 1)));
            node[1] = h_hash(pk_seed, a, load16(auth + k * N), node[0]);
        } else {
            a.set_tree_index((idx >> (k + 1)));
            node[1] = h_hash(pk_seed, a, node[0], load16(auth + k * N));
        }
        node[0] = node[1];
    }
    return node[0];
}

// ── Hypertree (FIPS 205 §7, Algorithms 12–13) ───────────────────────────────

void ht_sign(const bytes16 &msg, const bytes16 &sk_seed, const bytes16 &pk_seed, uint64_t idx_tree,
             uint32_t idx_leaf, uint8_t *sig_ht) noexcept {
    // Algorithm 12: sign with the bottom tree, then chain XMSS public keys
    // up the layers; idx_tree >>= h' between layers.
    Adrs adrs{};
    adrs.set_tree(idx_tree);
    bytes16 root = msg;
    size_t off = 0;
    for (unsigned layer = 0; layer < D; ++layer) {
        adrs.set_layer(layer);
        xmss_sign(pk_seed, sk_seed, idx_leaf, root, adrs, sig_ht + off);
        off += (LEN + HP) * N;
        if (layer < D - 1) {
            root = xmss_pk_from_sig(idx_leaf, sig_ht + off - (LEN + HP) * N, root, pk_seed, adrs);
            idx_leaf = static_cast<uint32_t>(idx_tree & ((1u << HP) - 1));
            idx_tree >>= HP;
            adrs.set_tree(idx_tree);
        }
    }
}

bool ht_verify(const bytes16 &msg, const uint8_t *sig_ht, const bytes16 &pk_seed, uint64_t idx_tree,
               uint32_t idx_leaf, const bytes16 &pk_root) noexcept {
    // Algorithm 13: d calls to xmss_pkFromSig; the top root must equal
    // PK.root. ADRS.setTreeAddress(idx_tree >> (layer * h')).
    Adrs adrs{};
    bytes16 node = msg;
    size_t off = 0;
    for (unsigned layer = 0; layer < D; ++layer) {
        adrs.set_layer(layer);
        adrs.set_tree(idx_tree);
        node = xmss_pk_from_sig(idx_leaf, sig_ht + off, node, pk_seed, adrs);
        off += (LEN + HP) * N;
        if (layer < D - 1) {
            idx_leaf = static_cast<uint32_t>(idx_tree & ((1u << HP) - 1));
            idx_tree >>= HP;
        }
    }
    return node == load16(pk_root.data());
}

// ── FORS (FIPS 205 §8, Algorithms 14–17) ────────────────────────────────────

bytes16 fors_sk_gen(const bytes16 &pk_seed, const bytes16 &sk_seed, const Adrs &adrs,
                    uint32_t idx) noexcept {
    // Algorithm 14: skADRS = copy of ADRS with type FORS_PRF, keyPair kept,
    // treeIndex = idx. sk = PRF(PK.seed, SK.seed, skADRS).
    Adrs sk_adrs = adrs;
    sk_adrs.set_type_and_clear(ADRS_FORS_PRF);
    sk_adrs.set_kp(adrs.kp());
    sk_adrs.set_hash(idx);
    return prf(pk_seed, sk_seed, sk_adrs);
}

bytes16 fors_node(const bytes16 &pk_seed, const bytes16 &sk_seed, const Adrs &adrs, uint32_t idx,
                  unsigned z) noexcept {
    // Algorithm 15: leaf = F(sk); internal = H(l || r) with FORS_TREE type.
    if (z == 0) {
        const bytes16 sk = fors_sk_gen(pk_seed, sk_seed, adrs, idx);
        Adrs a = adrs;
        a.set_tree_height(0);
        a.set_hash(idx);
        return chain_hash(pk_seed, a, sk);
    }
    const bytes16 lnode = fors_node(pk_seed, sk_seed, adrs, idx * 2, z - 1);
    const bytes16 rnode = fors_node(pk_seed, sk_seed, adrs, idx * 2 + 1, z - 1);
    Adrs a = adrs;
    a.set_tree_height(z);
    a.set_hash(idx);
    return h_hash(pk_seed, a, lnode, rnode);
}

void fors_sign(const bytes16 &sk_seed, const bytes16 &pk_seed, const Adrs &adrs, const uint8_t *md,
               uint8_t *sig_fors) noexcept {
    // Algorithm 16: indices = base_2b(md, a, k); for each tree i:
    // sk = fors_skGen(i*2^a + indices[i]); AUTH[j] = node(i*2^(a-j) + s, j),
    // s = floor(indices[i]/2^j) ^ 1.
    uint32_t indices[K];
    base_2b(indices, md, A, K);
    const size_t kForsSigNode = (A + 1) * N;
    for (unsigned i = 0; i < K; ++i) {
        uint8_t *out = sig_fors + i * kForsSigNode;
        const bytes16 sk = fors_sk_gen(pk_seed, sk_seed, adrs, i * (1u << A) + indices[i]);
        std::memcpy(out, sk.data(), N);
        for (unsigned j = 0; j < A; ++j) {
            const uint32_t s = (indices[i] >> j) ^ 1;
            const bytes16 auth = fors_node(pk_seed, sk_seed, adrs, i * (1u << (A - j)) + s, j);
            std::memcpy(out + N + j * N, auth.data(), N);
        }
    }
}

void fors_pk_from_sig(const bytes16 &pk_seed, const Adrs &adrs, const uint8_t *md,
                      const uint8_t *sig_fors, bytes16 &pk_out) noexcept {
    // Algorithm 17: roots[i] computed from sk and AUTH; pk = T_k(roots).
    uint32_t indices[K];
    base_2b(indices, md, A, K);
    const size_t kForsSigNode = (A + 1) * N;
    bytes16 roots[K];
    for (unsigned i = 0; i < K; ++i) {
        const uint8_t *node_sig = sig_fors + i * kForsSigNode;
        Adrs a = adrs;
        a.set_tree_height(0);
        a.set_hash(i * (1u << A) + indices[i]);
        bytes16 node = chain_hash(pk_seed, a, load16(node_sig));
        for (unsigned j = 0; j < A; ++j) {
            a.set_tree_height(j + 1);
            if ((indices[i] >> j) & 1u) {
                // Parent is the right child: node = H(auth || node).
                a.set_tree_index((i * (1u << A) + indices[i]) >> (j + 1));
                node = h_hash(pk_seed, a, load16(node_sig + N + j * N), node);
            } else {
                a.set_tree_index((i * (1u << A) + indices[i]) >> (j + 1));
                node = h_hash(pk_seed, a, node, load16(node_sig + N + j * N));
            }
        }
        roots[i] = node;
    }
    Adrs pk_adrs = adrs;
    pk_adrs.set_type_and_clear(ADRS_FORS_ROOTS);
    pk_adrs.set_kp(adrs.kp());
    pk_out = t_hash(pk_seed, pk_adrs, reinterpret_cast<const uint8_t *>(roots), K * N);
}

// ── SLH-DSA top level (FIPS 205 §9, Algorithms 18–20) ───────────────────────

SlhSk slh_keygen(const bytes16 &sk_seed, const bytes16 &sk_prf, const bytes16 &pk_seed) noexcept {
    // Algorithm 18: PK.root = xmss_node(SK.seed, 0, h', PK.seed, layer d-1).
    Adrs adrs{};
    adrs.set_layer(D - 1);
    const bytes16 root = xmss_node(pk_seed, sk_seed, 0, 0, HP, adrs);
    SlhSk sk{};
    sk.sk_seed = sk_seed;
    sk.sk_prf = sk_prf;
    sk.pk_seed = pk_seed;
    sk.pk_root = root;
    return sk;
}

bytes64 serialize_sk(const SlhSk &sk) noexcept {
    bytes64 out{};
    std::memcpy(out.data(), sk.sk_seed.data(), N);
    std::memcpy(out.data() + N, sk.sk_prf.data(), N);
    std::memcpy(out.data() + 2 * N, sk.pk_seed.data(), N);
    std::memcpy(out.data() + 3 * N, sk.pk_root.data(), N);
    return out;
}

bytes32 serialize_pk(const SlhPk &pk) noexcept {
    bytes32 out{};
    std::memcpy(out.data(), pk.pk_seed.data(), N);
    std::memcpy(out.data() + N, pk.pk_root.data(), N);
    return out;
}

// Shared body of Algorithm 19 after the digest: R goes first in the
// signature, then the digest split (byte-aligned, no bit shifts): md =
// digest[0:21] (k*a = 168 bits), tmp_idxtree = digest[21:28] (7 bytes),
// tmp_idxleaf = digest[28:30] (2 bytes). idx_tree = toInt(tmp_idxtree) mod
// 2^(h-h'); idx_leaf = toInt(tmp_idxleaf) mod 2^h' — mod, NOT shift. FORS
// signature on md; HT signature on the FORS public key.
void slh_sign_body(const SlhSk &sk, const bytes16 &r, const bytes32 &digest, Sig &sig) noexcept {
    std::memcpy(sig.data(), r.data(), N);

    const uint64_t idx_tree = to_int(digest.data() + 21, 7) & ((1ULL << (H - HP)) - 1);
    const uint32_t idx_leaf =
        static_cast<uint32_t>(to_int(digest.data() + 28, 2) & ((1u << HP) - 1));

    Adrs adrs{};
    adrs.set_tree(idx_tree);
    adrs.set_type_and_clear(ADRS_FORS_TREE);
    adrs.set_kp(idx_leaf);

    fors_sign(sk.sk_seed, sk.pk_seed, adrs, digest.data(), sig.data() + N);
    bytes16 pk_fors;
    fors_pk_from_sig(sk.pk_seed, adrs, digest.data(), sig.data() + N, pk_fors);

    ht_sign(pk_fors, sk.sk_seed, sk.pk_seed, idx_tree, idx_leaf, sig.data() + N + K * (A + 1) * N);
}

// Shared body of Algorithm 20 after the digest: FORS pk from the candidate
// signature, HT verify against PK.root.
bool slh_verify_body(const SlhPk &pk, const bytes32 &digest, const Sig &sig) noexcept {
    const uint64_t idx_tree = to_int(digest.data() + 21, 7) & ((1ULL << (H - HP)) - 1);
    const uint32_t idx_leaf =
        static_cast<uint32_t>(to_int(digest.data() + 28, 2) & ((1u << HP) - 1));

    Adrs adrs{};
    adrs.set_tree(idx_tree);
    adrs.set_type_and_clear(ADRS_FORS_TREE);
    adrs.set_kp(idx_leaf);

    bytes16 pk_fors;
    fors_pk_from_sig(pk.pk_seed, adrs, digest.data(), sig.data() + N, pk_fors);

    return ht_verify(pk_fors, sig.data() + N + K * (A + 1) * N, pk.pk_seed, idx_tree, idx_leaf,
                     pk.pk_root);
}

// slh_sign_internal (Algorithm 19): M' is absorbed directly — the internal
// interface takes M' as-is (the ACVP internalProjection sigVer vectors are
// internal-interface). Randomized variant: opt_rand = addrnd when provided,
// PK.seed otherwise (the deterministic variant).
bool slh_sign_internal(const SlhSk &sk, const uint8_t *m_prime, size_t m_prime_len,
                       const uint8_t *addrnd, size_t addrnd_len, Sig &sig) noexcept {
    // opt_rand is either exactly n bytes (the hedged variant) or absent
    // (deterministic). A partial addrnd would be an overread of the
    // caller's buffer — refuse it.
    if (addrnd_len != 0 && addrnd_len != N)
        return false;
    const bytes16 opt_rand = addrnd_len ? load16(addrnd) : sk.pk_seed;
    bytes16 r{};
    bytes32 digest{};
    prf_msg_internal(sk.sk_prf, opt_rand, m_prime, m_prime_len, r);
    msg_hash_internal(r, sk.pk_seed, sk.pk_root, m_prime, m_prime_len, digest);
    slh_sign_body(sk, r, digest, sig);
    return true;
}

// slh_verify_internal (Algorithm 20): M' direct.
bool slh_verify_internal(const SlhPk &pk, const uint8_t *m_prime, size_t m_prime_len,
                         const Sig &sig) noexcept {
    const bytes16 r = load16(sig.data());
    bytes32 digest{};
    msg_hash_internal(r, pk.pk_seed, pk.pk_root, m_prime, m_prime_len, digest);
    return slh_verify_body(pk, digest, sig);
}

bool slh_sign(const SlhSk &sk, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
              size_t ctx_len, const uint8_t *addrnd, size_t addrnd_len, Sig &sig) noexcept {
    // Algorithm 19 external wrapper: M' = toByte(0,1) || toByte(len(ctx),1) ||
    // ctx || M is absorbed in pieces — no fixed-size buffer, so messages of
    // any length hash identically. Fail-closed: a context longer than 255
    // cannot be encoded in the one-byte length field, and a partial addrnd
    // would be an overread — the caller MUST check the return value (a
    // false return leaves `sig` untouched, never a half-signed artifact).
    if (ctx_len > 255)
        return false;
    if (addrnd_len != 0 && addrnd_len != N)
        return false;
    const bytes16 opt_rand = addrnd_len ? load16(addrnd) : sk.pk_seed;
    bytes16 r{};
    bytes32 digest{};
    if (!prf_msg(sk.sk_prf, opt_rand, msg, msg_len, ctx, ctx_len, r))
        return false;
    if (!msg_hash(r, sk.pk_seed, sk.pk_root, msg, msg_len, ctx, ctx_len, digest))
        return false;
    slh_sign_body(sk, r, digest, sig);
    return true;
}

Sig slh_sign_det(const SlhSk &sk, const uint8_t *msg, size_t msg_len) noexcept {
    Sig sig{};
    // No ctx, no addrnd: the fail-closed guards below cannot fire here.
    (void)slh_sign(sk, msg, msg_len, nullptr, 0, nullptr, 0, sig);
    return sig;
}

bool slh_verify(const SlhPk &pk, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                size_t ctx_len, const Sig &sig) noexcept {
    // Algorithm 20 external wrapper: M' = toByte(0,1) || toByte(len(ctx),1) ||
    // ctx || M is absorbed in pieces. The R from the signature is used, not
    // regenerated.
    const bytes16 r = load16(sig.data());
    bytes32 digest{};
    if (!msg_hash(r, pk.pk_seed, pk.pk_root, msg, msg_len, ctx, ctx_len, digest))
        return false;
    return slh_verify_body(pk, digest, sig);
}

} // namespace vx::crypto::slh
