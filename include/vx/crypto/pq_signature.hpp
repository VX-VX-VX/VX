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
#include <bitset>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <mutex>
#include <string>
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

/// The public mask seed for a master secret key, derived exactly as
/// pq_sign_transaction derives it internally ("VX_PQ_PUBSEED_V1" || sk).
/// Exposed so protocol code can compute an account's XMSS root (its
/// PQ binding) without signing anything.
std::array<uint8_t, 32> pub_seed_from_sk(const std::array<uint8_t, 32>& sk) noexcept;

// ── Tree rollover (BACKLOG 1.5, delivered v0.0.13) ──────────────────────────
//
// The account's master key spans ONE flat WOTS+ hypertree with a 32-bit
// global leaf namespace: global_leaf = (tree_index << XMSS_H) | leaf_idx.
// Window 0 (leaves 0..15) is the published account key with the FROZEN
// derivation — for tree_index 0 every value below is byte-identical with
// the pre-rollover behavior. Tree rollover advances the account to the
// NEXT 16-leaf window: xmss_root_tree(master_sk, pub_seed, t) is the root
// over global leaves (t<<4)|0..(t<<4)|15, derived from the same master key
// and mask seed, so windows share no leaves and no roots.
//
// The 2376-byte witness stays frozen: pq_sign_message now builds the root
// and auth path over the SAME global-leaf window its signature draws the
// secret chains from (previously it signed window-t leaves against a
// window-0 tree — the incoherence that forced the nonce>15 refusal), and
// pq_verify_wots_xmss needs no change: it walks the auth path inside the
// transported root's window using leaf_index & 0xF.
//
// Binding windows to ONE account without growing the witness uses the
// XMSS^MT certification construction: the LAST leaf (15) of window t signs
// a rollover certificate over window u's root. A verifier chains
// certificates from the account's published root (window 0); the
// certificate burns leaf 15 of the old window exactly like a transaction
// leaf (reserve it in the PqLeafLedger under the old root). After a
// rollover out of window t, that window is fully spent and MUST NOT sign
// again — enforcing that policy at the wallet/consensus layer is the
// remaining BACKLOG 1.5 item (together with the acceptance policy for a
// rotated root, which today is NOT wired into any consensus rule).
//
// Leaf-namespace capacity: the top XMSS_H bits of global_leaf are the leaf
// itself, so the valid tree_index domain is 0..PQ_MAX_SUBTREE_INDEX.
inline constexpr uint32_t PQ_MAX_SUBTREE_INDEX =
    static_cast<uint32_t>(0xFFFFFFFFu) >> XMSS_H; // 0x0FFFFFFF

// The certificate leaf: the LAST leaf of the certifying window.
inline constexpr unsigned PQ_ROLLOVER_CERT_LEAF = XMSS_LEAVES - 1; // leaf 15

// Root of window t — the PQ public key a rollover certificate publishes for
// the target window. Equals xmss_root() for t == 0 (frozen epoch 0).
std::array<uint8_t, 32> xmss_root_tree(const std::array<uint8_t, 32>& master_sk,
                                       const std::array<uint8_t, 32>& pub_seed,
                                       uint32_t tree_index) noexcept;

// M = Sponge256("VX_PQ_ROLLOVER_V1" || old_root[32] || u32(from_tree)
//               || u32(to_tree) || new_root[32]) — 32 bytes.
std::array<uint8_t, 32> rollover_binding_digest(
    const std::array<uint8_t, 32>& old_root, uint32_t from_tree, uint32_t to_tree,
    const std::array<uint8_t, 32>& new_root) noexcept;

// Signs the rollover certificate window from_tree -> to_tree: a full
// PqSignatureWitness by leaf 15 of window from_tree over the binding
// digest, with the account mask seed derived exactly as
// pq_sign_transaction derives it ("VX_PQ_PUBSEED_V1" || master_sk).
// Refuses from_tree == to_tree or any index beyond PQ_MAX_SUBTREE_INDEX
// by returning a default witness whose verification fails.
PqSignatureWitness pq_sign_rollover(const std::array<uint8_t, 32>& master_sk,
                                    uint32_t from_tree, uint32_t to_tree) noexcept;

// Verifies a rollover certificate end-to-end: the leaf and window policy
// (leaf 15 of from_tree), the certificate root equals old_root, the
// transported witness commitment matches the content, and the WOTS+/XMSS
// chain verifies over the binding digest of THIS (old_root, from, to,
// new_root) tuple. Fail-closed: any disagreement refuses.
bool pq_verify_rollover(const std::array<uint8_t, 32>& old_root, uint32_t from_tree,
                        uint32_t to_tree, const std::array<uint8_t, 32>& new_root,
                        const PqSignatureWitness& cert) noexcept;

// ── Sign / verify ────────────────────────────────────────────────────────────
// Signs `msg` with leaf `leaf_idx` of the tree whose key material is
// (master_sk, pub_seed); fills the whole witness including pq_pubkey_root
// and witness_digest. For rollover trees pass tree_sk/tree_pub_seed — the
// witness is then coherent inside THAT tree (see the rollover section).
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
/// Rebuilds the SegPQ anchor (tx.cocoon_proof) for a transaction from its
/// witness: trunc12(Sponge("VX_SEGPQ_ANCHOR_V1" || msg || root ||
/// witness_digest)). Used when a node reconstructs a client-supplied
/// transaction — the anchor is derived from the witness, never trusted from
/// the wire.
void pq_set_transaction_anchor(blockchain::Transaction& tx,
                               const PqSignatureWitness& w) noexcept;

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
    // The leaf this call actually signed with (0..15). Reported per call so
    // concurrent signers of the *same* message can each name their own
    // witness — the by-digest registry alone cannot distinguish them.
    uint32_t used_leaf_index = 0xFFFFFFFFu;
};

// Signs the 112-byte transaction with a post-quantum WOTS+/XMSS key:
//   1. master_sk is committed into a mlock'ed MemoryVault page and consumed
//      (read-once → page BURNED),
//   2. the one-time leaf is reserved in `leaf_ledger` when provided (see
//      PqLeafLedger): a leaf that already signed is never reused — the
//      caller receives the lowest free leaf instead of the nonce-derived
//      one, and exhausting all 16 leaves of the key fails the call,
//   3. the witness is generated; every secret chain scratch buffer is
//      zeroized + _mm_clflush'd via scrub_execution_state,
//   4. full_tag = Sponge256("VX_SEGPQ_ANCHOR_V1" || msg || pq_pubkey_root ||
//      witness_digest); tx.cocoon_proof = trunc12(full_tag),
//   5. the witness is registered in the PqWitnessRegistry bound to
//      (tx_msg_digest, sender_nfa → pq_pubkey_root).
//
// Returns false only when a ledger was supplied and no leaf could be
// reserved (all 16 consumed, or the durable log failed validation —
// signing must not proceed). Without a ledger the call never fails and
// offers no reuse protection (legacy in-memory behavior).
bool pq_sign_transaction(blockchain::Transaction& tx,
                         const std::array<uint8_t, 32>& master_sk,
                         PqSignTimings* timings = nullptr,
                         class PqLeafLedger* leaf_ledger = nullptr,
                         PqSignatureWitness* out_witness = nullptr) noexcept;

// ── PqLeafLedger (one-time-leaf lifecycle) ───────────────────────────────────

// Makes the "every one-time key is used exactly once" property real state
// instead of an assumption:
//   - two signatures with the same nonce get different leaves,
//   - a process restart keeps the consumed-leaf history (durable mode),
//   - concurrent threads and processes are serialized on the same ledger.
//
// Durable mode (non-empty path) stores 33-byte append-only records
// (32-byte key root + 1-byte leaf index), written and fsync'd BEFORE the
// signature is produced: a crash may burn a leaf without emitting its
// signature — fail-closed — but never emit a signature without burning
// the leaf. The log is re-read under an exclusive flock on every
// reservation, so two node processes sharing a data directory cannot
// double-spend a leaf. If the log is unreadable or carries an invalid
// record, the ledger fails closed: reserve() returns -1 forever.
//
// Memory-only mode (empty path) keeps the same guarantees within one
// process lifetime; it exists for tests and callers without a data
// directory.
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

class PqLeafLedger {
public:
    static constexpr unsigned kLeaves = static_cast<unsigned>(XMSS_LEAVES); // 16 per key

    explicit PqLeafLedger(std::string path = "");
    ~PqLeafLedger();
    PqLeafLedger(const PqLeafLedger&) = delete;
    PqLeafLedger& operator=(const PqLeafLedger&) = delete;

    // Reserve a leaf for `key_root`: `requested_leaf` when free, otherwise
    // the lowest free leaf of that key. Returns the assigned leaf index
    // (0..15), or -1 when all leaves are consumed (or, in durable mode,
    // when the log cannot be trusted).
    int reserve(const std::array<uint8_t, 32>& key_root, unsigned requested_leaf);

    // Number of consumed leaves for this key (0..16).
    size_t used_count(const std::array<uint8_t, 32>& key_root) const;

private:
    bool parse_log_locked(); // rebuilds used_ from the file; false = corrupt
    bool append_locked(const std::array<uint8_t, 32>& key_root, unsigned leaf);

    mutable std::mutex mu_;
    std::unordered_map<std::array<uint8_t, 32>, std::bitset<kLeaves>, PqArrayHash> used_;
    std::string path_;
    int fd_ = -1;
    // memory_only_: no path was requested — in-process history is the
    // whole contract. durable_ok_: the durable log validated; when a path
    // was requested but the log fails to open/parse, BOTH stay false and
    // reserve() refuses forever (fail-closed, never a silent fallback).
    bool memory_only_ = false;
    bool durable_ok_ = false;
};

// ── PqWitnessRegistry (in-memory SegPQ sidecar) ──────────────────────────────

class PqWitnessRegistry {
public:
    static PqWitnessRegistry& instance() noexcept;

    // Hardening (external round-7 review): the registry is a CACHE, never an
    // authority - nothing enters it unverified, duplicates are not stored
    // twice, and a digest may hold several candidates so an attacker cannot
    // occupy a slot and censor the honest witness.
    static constexpr size_t kMaxWitnessesPerDigest = 8;
    static constexpr size_t kMaxDigestEntries = 50000;

    // Binds a freshly signed witness to its message digest and sender.
    // Verifies the FULL WOTS+/XMSS + anchor chain against the tx first;
    // returns false (and registers nothing) when the witness is invalid.
    bool register_witness(const blockchain::Transaction& tx,
                          const PqSignatureWitness& w);

    // Registers a witness that arrived WITHOUT its transaction (wire
    // WITNESS records, peer relay): the sender and the message digest are
    // carried explicitly. Also used by the durable-log replay. Verifies the
    // witness commitment and the WOTS+/XMSS chain against the CLAIMED
    // digest before storing; returns false otherwise.
    bool register_witness_bytes(const std::array<uint8_t, 32>& msg_digest,
                                const uint8_t sender_nfa[42],
                                const PqSignatureWitness& w);

    // Durable witness sidecar (BACKLOG 0.8): <ledger>.pqw holds
    // "VXPQWT1" + digest(32) + sender(42) + witness(2376) records, appended
    // and fsync'd on every registration. attach_durable_log(path) replays
    // the existing log into memory first; a short or corrupt trailing
    // record stops the replay (fail-closed: partial witnesses are not
    // trusted). Registration without an attached log stays memory-only
    // (tests, one-shot tools).
    void attach_durable_log(const std::string& path);

    // Is this sender backed by a post-quantum key?
    bool is_pq_sender(const uint8_t sender_nfa[42]) const;

    // Witness lookup by canonical message digest (first candidate —
    // compatibility/diagnostics use).
    bool lookup(const std::array<uint8_t, 32>& msg_digest,
                PqSignatureWitness& out) const;

    // Consensus lookup: returns the first candidate for this transaction's
    // digest that passes the FULL WOTS+/XMSS + SegPQ-anchor verification
    // against THIS tx. A digest may hold several candidates (an attacker
    // can register a cryptographically valid signature for a digest they
    // predict - it just will not verify against the honest transaction).
    bool lookup_verifying(const blockchain::Transaction& tx,
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
    bool append_durable_locked(const std::array<uint8_t, 32>& digest,
                               const std::array<uint8_t, 42>& sender,
                               const PqSignatureWitness& w);

    mutable std::mutex mutex_;
    std::unordered_map<std::array<uint8_t, 32>, std::vector<Entry>, PqArrayHash> by_digest_;
    std::unordered_map<std::array<uint8_t, 42>, std::array<uint8_t, 32>, PqArrayHash> sender_roots_;
    blockchain::Transaction last_tx_{};
    PqSignatureWitness last_witness_{};
    bool has_last_ = false;
    int durable_fd_ = -1;
    std::string durable_path_;
    bool durable_locked_ = false; // flock held on the sidecar
};

} // namespace vx::crypto::pq
