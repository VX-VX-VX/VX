// FIPS 205 — SLH-DSA-SHAKE-128s: stateless hash-based signatures.
//
// The second signature backend of the 0.2.x line (Phase B). Unlike the
// in-tree WOTS+/XMSS custom-sponge engine (pq_signature.hpp), this is the
// NIST standard verbatim — bit-exact against the ACVP-Server vectors, the
// same gate discipline as ML-KEM-768. Purpose: the committee/threshold
// track (Phases C–D) needs a stateless signature whose private key never
// carries per-message state, so share holders cannot be deanonymized by
// leaf accounting.
//
// KAT gate: tests/test_slh_dsa_acvp.cpp pins the ACVP sigVer SHAKE-128s
// internalProjection group bit-for-bit — a sign() that does not reproduce
// the ACVP signature is a shipped bug, never a tolerance issue.
//
// Parameters (FIPS 205 Table 2, SLH-DSA-SHAKE-128s):
//   n=16, h=63, d=7, h'=9, a=12, k=14, w=16, len_1=32, len_2=3, len=35,
//   m=30 (240 bits: 63 tree + 9 leaf + 168 FORS, no discard),
//   signature 7856 B = 16(R) + 2912(FORS: 14×13×16) + 4928(HT: 7×(560+144)).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace vx::crypto::slh {

inline constexpr unsigned N = 16;            // security parameter (bytes)
inline constexpr unsigned H = 63;            // total hypertree height (bits)
inline constexpr unsigned D = 7;             // hypertree layers
inline constexpr unsigned HP = 9;            // layer height h' = h/d
inline constexpr unsigned A = 12;            // FORS tree height
inline constexpr unsigned K = 14;            // FORS trees
inline constexpr unsigned W = 16;            // Winternitz parameter
inline constexpr unsigned LOGW = 4;          // lg(w)
inline constexpr unsigned LEN1 = 32;         // len_1 = ceil(8n/lgw) = 32 chains
inline constexpr unsigned LEN2 = 3;          // checksum chains: floor(lg(len1*(w-1))/4)+1
inline constexpr unsigned LEN = LEN1 + LEN2; // 35 WOTS+ chains
inline constexpr unsigned M = 30;            // H_msg output bytes (240 bits)
inline constexpr size_t SIG_BYTES = 7856;
inline constexpr size_t PK_BYTES = 32; // pk.seed || pk.root
inline constexpr size_t SK_BYTES = 64; // sk.seed || sk.prf || pk.seed || pk.root

using bytes16 = std::array<uint8_t, N>;
using bytes32 = std::array<uint8_t, 2 * N>;
using bytes64 = std::array<uint8_t, SK_BYTES>;
using Sig = std::array<uint8_t, SIG_BYTES>;

// ADRS — the 32-byte hash address (FIPS 205 §7.2):
//   layer[4] | tree[12] | type[4] | keyPair[4] | chain[4] | hash[4]
struct Adrs {
    uint8_t b[32] = {};

    void set_layer(uint32_t v) noexcept; // layer address (top hypertree layer)
    void set_tree(uint64_t v) noexcept;  // tree address (bits 31..0 of the 63-bit index)
    void set_type(uint32_t v) noexcept;
    void set_kp(uint32_t v) noexcept; // key pair address
    void set_chain(uint32_t v) noexcept;
    void set_hash(uint32_t v) noexcept;

    uint64_t tree() const noexcept;
    uint32_t layer() const noexcept;

    // setTypeAndClear(t): type = t; keyPair/chain/hash = 0.
    void set_type_and_clear(uint32_t t) noexcept;
    // setType(t): type = t, all other fields preserved (the WOTS_KEY_GEN
    // derivation chain reuses the cleared ADRS with a different type).
    void set_type_keep(uint32_t t) noexcept;

    // FORS/MERKLE tree height aliases the chain-address field (bytes 24-27);
    // tree index aliases the hash-address field (bytes 28-31). FIPS 205 §7.2.
    uint32_t get_tree_height() const noexcept {
        return chain();
    }
    void set_tree_height(uint32_t v) noexcept {
        set_chain(v);
    }
    uint32_t get_tree_index() const noexcept {
        return hash();
    }
    void set_tree_index(uint32_t v) noexcept {
        set_hash(v);
    }
    uint32_t get_key_pair() const noexcept {
        return kp();
    }
    void set_key_pair(uint32_t v) noexcept {
        set_kp(v);
    }
    uint32_t get_chain_address() const noexcept {
        return chain();
    }
    void set_chain_address(uint32_t v) noexcept {
        set_chain(v);
    }
    uint32_t get_hash_address() const noexcept {
        return hash();
    }
    void set_hash_address(uint32_t v) noexcept {
        set_hash(v);
    }
    uint32_t kp() const noexcept;
    uint32_t chain() const noexcept;
    uint32_t hash() const noexcept;
};

// ADRS types (FIPS 205 Table 6).
inline constexpr uint32_t ADRS_WOTS_HASH = 0;
inline constexpr uint32_t ADRS_WOTS_PK = 1;
inline constexpr uint32_t ADRS_TREE = 2;
inline constexpr uint32_t ADRS_FORS_TREE = 3;
inline constexpr uint32_t ADRS_FORS_ROOTS = 4;
inline constexpr uint32_t ADRS_WOTS_PRF = 5;
inline constexpr uint32_t ADRS_FORS_PRF = 6;

// ── Primitives (FIPS 205 §11.1) ─────────────────────────────────────────────
// All outputs are n bytes (16): F, H, T_l, PRF, PRF_msg each yield 8n bits.
bytes16 chain_hash(const bytes16 &pk_seed, const Adrs &adrs, const bytes16 &tmp) noexcept; // F
bytes16 t_hash(const bytes16 &pk_seed, const Adrs &adrs, const uint8_t *parts,
               size_t n) noexcept; // T_l
bytes16 h_hash(const bytes16 &pk_seed, const Adrs &adrs, const bytes16 &m1,
               const bytes16 &m2) noexcept; // H
bytes16 prf(const bytes16 &pk_seed, const bytes16 &sk_seed, const Adrs &adrs) noexcept;
// M' = toByte(0,1) || toByte(len(ctx),1) || ctx || M is absorbed in pieces —
// never materialized (messages may be arbitrarily long). addrnd is NOT part
// of M' — it feeds PRF_msg as opt_rand. Returns false when ctx_len > 255
// (the one-byte context length field cannot encode it).
bool prf_msg(const bytes16 &sk_prf, const bytes16 &opt_rand, const uint8_t *msg, size_t msg_len,
             const uint8_t *ctx, size_t ctx_len, bytes16 &out) noexcept;
// H_msg = SHAKE256(R || PK.seed || PK.root || M', 30)
bool msg_hash(const bytes16 &r, const bytes16 &pk_seed, const bytes16 &pk_root, const uint8_t *msg,
              size_t msg_len, const uint8_t *ctx, size_t ctx_len, bytes32 &out) noexcept;

// ── WOTS+ (FIPS 205 §6.1, Algorithms 5–8) ───────────────────────────────────
// base_2^w representation + checksum, len_1+len_2 = 35 chains.
void wots_base(const uint8_t digest[32], uint8_t out_b[LEN]) noexcept;
// Chain the secret value through `steps` chain-hash steps.
// Algorithm 4 chain(X, i, s, ...): hash addresses run start_idx .. start_idx+steps-1.
// A fresh chain from the secret value uses start_idx = 0; a continuation from a
// signature element uses start_idx = b[i] (Algorithm 8).
bytes16 wots_chain(const bytes16 &pk_seed, const Adrs &adrs, const bytes16 &start,
                   unsigned start_idx, unsigned steps) noexcept;
void wots_pkgen(const bytes16 &pk_seed, const bytes16 &sk_seed, Adrs sk_adrs,
                bytes16 pk_out[LEN]) noexcept;
void wots_sign(const bytes16 &pk_seed, const bytes16 &sk_seed, const Adrs &sk_adrs,
               const uint8_t digest[32], bytes16 sig_out[LEN]) noexcept;
void wots_pk_from_sig(const bytes16 &pk_seed, const Adrs &adrs, const uint8_t digest[32],
                      const bytes16 sig[LEN], bytes16 pk_out[LEN]) noexcept;

// ── XMSS layer (FIPS 205 §6.2, Algorithms 9–11) ─────────────────────────────
bytes16 xmss_node(const bytes16 &pk_seed, const bytes16 &sk_seed, uint64_t tree_idx,
                  unsigned node_idx, unsigned height, Adrs adrs) noexcept;

// ── FORS (FIPS 205 §8, Algorithms 14–17) ────────────────────────────────────
bytes16 fors_node(const bytes16 &pk_seed, const bytes16 &sk_seed, const Adrs &adrs, uint32_t idx,
                  unsigned z) noexcept;
// Compute the FORS public key from a candidate signature (Algorithm 17).
// sig_fors points at k*(a+1)*n bytes; pk_out receives n bytes.
void fors_pk_from_sig(const bytes16 &pk_seed, const Adrs &adrs, const uint8_t *md,
                      const uint8_t *sig_fors, bytes16 &pk_out) noexcept;

// ── SLH-DSA top level (FIPS 205 §9, Algorithms 18–20) ───────────────────────
struct SlhSk {
    bytes16 sk_seed; // SK.seed
    bytes16 sk_prf;  // SK.prf
    bytes16 pk_seed; // PK.seed
    bytes16 pk_root; // PK.root
};

struct SlhPk {
    bytes16 pk_seed;
    bytes16 pk_root;
};

// slh_keygen_internal (Algorithm 18): SK.root = wots_pkgen over the
// WOTS_KEY_GEN address (layer 0, tree 0, keyPair 0).
SlhSk slh_keygen(const bytes16 &sk_seed, const bytes16 &sk_prf, const bytes16 &pk_seed) noexcept;

// Serialize: SK = sk.seed || sk.prf || pk.seed || pk.root (64 B); PK = pk.seed || pk.root (32 B).
bytes64 serialize_sk(const SlhSk &sk) noexcept;
bytes32 serialize_pk(const SlhPk &pk) noexcept;

// slh_sign (Algorithm 19, deterministic variant: addrnd = empty).
// sig = R || SIG_FORS || SIG_HT (7856 B). Returns false (fail-closed,
// `sig` untouched) when ctx_len > 255 (the one-byte context length field
// cannot encode it) or addrnd_len is neither 0 nor N — a partial addrnd
// would be an overread of the caller's buffer.
bool slh_sign(const SlhSk &sk, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
              size_t ctx_len, const uint8_t *addrnd, size_t addrnd_len, Sig &sig) noexcept;
// Convenience: deterministic sign with empty context (never fails).
Sig slh_sign_det(const SlhSk &sk, const uint8_t *msg, size_t msg_len) noexcept;

// slh_verify (Algorithm 20).
bool slh_verify(const SlhPk &pk, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                size_t ctx_len, const Sig &sig) noexcept;

// Internal interface (FIPS 205 §9.1): slh_sign_internal/slh_verify_internal
// take M' as-is — the M' = toByte(0,1) || toByte(len(ctx),1) || ctx || M
// wrapper belongs to the external slh_sign/slh_verify only. The ACVP
// internalProjection sigVer vectors are internal-interface: their message
// field IS M'.
bool slh_sign_internal(const SlhSk &sk, const uint8_t *m_prime, size_t m_prime_len,
                       const uint8_t *addrnd, size_t addrnd_len, Sig &sig) noexcept;
bool slh_verify_internal(const SlhPk &pk, const uint8_t *m_prime, size_t m_prime_len,
                         const Sig &sig) noexcept;

} // namespace vx::crypto::slh
