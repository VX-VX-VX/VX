#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Post-Quantum Hash-Based Signature Engine
//   WOTS+ (w=16, L=67 chains) + XMSS Merkle tree (H=4) over VortexSponge256.
//
// Security posture: every primitive is hash-based. There is NO operation
// vulnerable to Shor's algorithm (no factoring, no discrete log) — classical
// security 2^256 (sponge preimage), Grover-bounded to 2^128.
//
// SegPQ (Segregated Post-Quantum Witness): the 112-byte Transaction frame is
// untouched; the multi-kilobyte WOTS+/XMSS witness lives in an in-memory
// sidecar registry keyed by the canonical tx message digest, while a full
// 256-bit anchor is truncated into cocoon_proof[12] binding the frame to the
// witness. A sender registered as PQ-backed MUST carry a valid witness —
// keyless checksum recalculation is rejected.
// ─────────────────────────────────────────────────────────────────────────────

#include "vx/blockchain/block.hpp"

#include <array>
#include <cstdint>
#include <cstddef>
#include <mutex>
#include <unordered_map>

namespace vx::crypto::pq {

// ── Parameters ───────────────────────────────────────────────────────────────

inline constexpr uint32_t PQ_CHAIN_ID = 0x58564336u; // low 32 bits of "VXC6" chain id
inline constexpr unsigned WOTS_W = 16;               // Winternitz base (4-bit nibbles)
inline constexpr unsigned WOTS_STEPS = 15;           // w - 1 chain steps
inline constexpr size_t   WOTS_MSG_NIBBLES = 64;     // l1: 256-bit msg as 64 nibbles
inline constexpr size_t   WOTS_CKSUM_NIBBLES = 3;    // l2: C <= 960 < 16^3
inline constexpr size_t   WOTS_CHAINS = WOTS_MSG_NIBBLES + WOTS_CKSUM_NIBBLES; // 67
inline constexpr size_t   XMSS_H = 4;                // tree height
inline constexpr size_t   XMSS_LEAVES = size_t(1) << XMSS_H;                   // 16

struct PqSignatureWitness {
    uint32_t leaf_index = 0;                            // nonce & 0xF
    uint32_t subtree_index = 0;                         // nonce >> XMSS_H
    std::array<uint8_t, 32> pub_seed{};                 // public mask seed
    std::array<uint8_t, 32> pq_pubkey_root{};           // XMSS root (account PQ key)
    std::array<std::array<uint8_t, 32>, WOTS_CHAINS> wots_sig{}; // 67 chains (2144 B)
    std::array<std::array<uint8_t, 32>, XMSS_H> auth_path{};     // Merkle path (128 B)
    std::array<uint8_t, 32> witness_digest{};           // 256-bit witness commitment
};

static_assert(sizeof(PqSignatureWitness) == 2376, "witness must be exactly 2376 bytes");

// ── Canonical message digest ─────────────────────────────────────────────────
// M = Sponge256("VX_PQ_TX_MSG_V1" || sender[42] || receiver[42] || amount[8]
//               || fee[4] || nonce[4] || chain_id[4]) — 32 bytes.
std::array<uint8_t, 32> tx_msg_digest(const blockchain::Transaction& tx) noexcept;

// ── Winternitz base vector ───────────────────────────────────────────────────
// B = [m_0..m_63, c_0, c_1, c_2] where C = Σ(15 - m_i), max C = 960.
// Returns C. Any increase of a message nibble strictly decreases C — the
// Winternitz barrier against forward-chain forgery.
uint32_t winternitz_checksum(const uint8_t msg[32]) noexcept;
void wots_base_vector(const uint8_t msg[32], uint8_t out_b[WOTS_CHAINS]) noexcept;

// ── Masked hash chains ───────────────────────────────────────────────────────
// mask = Sponge256("VX_WOTS_MASK" || pub_seed || u16(ci) || u8(s))
// next = Sponge256("VX_WOTS_STEP" || (x ^ mask) || pub_seed || u16(ci) || u8(s))
std::array<uint8_t, 32> chain_step(const std::array<uint8_t, 32>& x,
                                   const std::array<uint8_t, 32>& pub_seed,
                                   uint16_t chain_idx, uint8_t step) noexcept;

// Applies `steps` steps starting from chain position `start`.
std::array<uint8_t, 32> chain_run(const std::array<uint8_t, 32>& x, unsigned start,
                                  unsigned steps, const std::array<uint8_t, 32>& pub_seed,
                                  uint16_t chain_idx) noexcept;

// ── Key material ─────────────────────────────────────────────────────────────
// sk_i = Sponge256("VX_WOTS_SK" || master_sk || u32(global_leaf) || u16(i));
// global_leaf = (subtree_index << XMSS_H) | leaf_idx so keys never repeat
// across subtrees. pk_i = Chain(sk_i, 0, 15); leaf root compresses 67 pk_i.
std::array<uint8_t, 32> wots_leaf_pk_root(uint32_t global_leaf,
                                          const std::array<uint8_t, 32>& master_sk,
                                          const std::array<uint8_t, 32>& pub_seed) noexcept;

// parent = Sponge256("VX_XMSS_NODE" || pub_seed || u8(level) || u16(node_idx)
//                     || left || right)
std::array<uint8_t, 32> xmss_node_hash(uint8_t level, uint16_t node_idx,
                                       const std::array<uint8_t, 32>& pub_seed,
                                       const std::array<uint8_t, 32>& left,
                                       const std::array<uint8_t, 32>& right) noexcept;

// Builds the full H=4 tree (16 WOTS+ leaves) and returns its root — the
// account's post-quantum public key (pq_pubkey_root).
std::array<uint8_t, 32> xmss_root(const std::array<uint8_t, 32>& master_sk,
                                  const std::array<uint8_t, 32>& pub_seed) noexcept;

// ── Sign / verify ────────────────────────────────────────────────────────────
// Signs `msg` with leaf `leaf_idx` of subtree 0's tree shape; fills the whole
// witness including pq_pubkey_root and witness_digest.
PqSignatureWitness pq_sign_message(uint32_t leaf_idx, uint32_t subtree_index,
                                   const std::array<uint8_t, 32>& master_sk,
                                   const std::array<uint8_t, 32>& pub_seed,
                                   const std::array<uint8_t, 32>& msg) noexcept;

// Pure WOTS+ + XMSS verification (no anchor): recomputes B from `msg`, walks
// each chain forward 15 - B[i] steps, rebuilds the root through the auth path
// and compares it with witness.pq_pubkey_root.
//
// Note on what this layer does NOT consume: subtree_index (signing-side
// metadata) and witness_digest (the commitment). Both are bound at the
// SegPQ anchor layer — pq_verify_transaction() recomputes the commitment
// from the witness content and refuses a witness whose transported digest
// field disagrees.
bool pq_verify_wots_xmss(const std::array<uint8_t, 32>& msg,
                         const PqSignatureWitness& w) noexcept;

// Recomputes the 256-bit witness commitment from the witness content. The
// same sponge the signer runs; exposed so tests and tooling can check that
// a transported witness_digest field matches the witness it travels with.
std::array<uint8_t, 32> witness_commitment(const PqSignatureWitness& w) noexcept;

// Full SegPQ verification: WOTS+/XMSS + the 256-bit anchor check against
// tx.cocoon_proof (trunc12 of the VX_SEGPQ_ANCHOR_V1 binding).
bool pq_verify_transaction(const blockchain::Transaction& tx,
                           const PqSignatureWitness& w) noexcept;

// ── SegPQ transaction signing (MemoryVault-protected) ──────────────────────

struct PqSignTimings {
    uint64_t keygen_cycles = 0;
    uint64_t sign_cycles = 0;
    double keygen_us = 0.0;
    double sign_us = 0.0;
    double verify_us = 0.0;
    bool vault_burn_verified = false;
};

// Signs the 112-byte transaction with a post-quantum WOTS+/XMSS key:
//   1. master_sk is committed into a mlock'ed MemoryVault page and consumed
//      (read-once → page BURNED),
//   2. the witness is generated; every secret chain scratch buffer is
//      zeroized + _mm_clflush'd via scrub_execution_state,
//   3. full_tag = Sponge256("VX_SEGPQ_ANCHOR_V1" || msg || pq_pubkey_root ||
//      witness_digest); tx.cocoon_proof = trunc12(full_tag),
//   4. the witness is registered in the PqWitnessRegistry bound to
//      (tx_msg_digest, sender_nfa → pq_pubkey_root).
void pq_sign_transaction(blockchain::Transaction& tx,
                         const std::array<uint8_t, 32>& master_sk,
                         PqSignTimings* timings = nullptr) noexcept;

// ── PqWitnessRegistry (in-memory SegPQ sidecar) ──────────────────────────────

// std::hash has no std::array overload — byte-mixing hasher for map keys.
struct PqArrayHash {
    template <size_t N>
    size_t operator()(const std::array<uint8_t, N>& a) const noexcept {
        uint64_t h = 1469598103934665603ull;
        for (size_t i = 0; i < N; ++i) {
            h ^= a[i];
            h *= 1099511628211ull;
        }
        return static_cast<size_t>(h);
    }
};

class PqWitnessRegistry {
public:
    static PqWitnessRegistry& instance() noexcept;

    // Binds a freshly signed witness to its message digest and sender.
    void register_witness(const blockchain::Transaction& tx,
                          const PqSignatureWitness& w);

    // Is this sender backed by a post-quantum key?
    bool is_pq_sender(const uint8_t sender_nfa[42]) const;

    // Witness lookup by canonical message digest; optionally returns the
    // root that was registered together with it.
    bool lookup(const std::array<uint8_t, 32>& msg_digest,
                PqSignatureWitness& out) const;

    // Last signed transaction + witness (RPC demo state).
    void set_last(const blockchain::Transaction& tx, const PqSignatureWitness& w);
    bool get_last(blockchain::Transaction& tx, PqSignatureWitness& w) const;

    size_t registered_count() const;

private:
    struct Entry {
        PqSignatureWitness witness;
        std::array<uint8_t, 42> sender{};
    };
    mutable std::mutex mutex_;
    std::unordered_map<std::array<uint8_t, 32>, Entry, PqArrayHash> by_digest_;
    std::unordered_map<std::array<uint8_t, 42>, std::array<uint8_t, 32>, PqArrayHash> sender_roots_;
    blockchain::Transaction last_tx_{};
    PqSignatureWitness last_witness_{};
    bool has_last_ = false;
};

} // namespace vx::crypto::pq
