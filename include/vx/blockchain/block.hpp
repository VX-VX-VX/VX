#pragma once

#include <cstdint>
#include <cstring>
#include <array>
#include <cstddef>
#include <span>
#include <string>

namespace vx::crypto::pq { struct PqSignatureWitness; } // forward decl (pq_signature.hpp)

namespace vx::blockchain {

// ── fixed-field tag copy ─────────────────────────────────────────────────────
// Copy a string-literal tag into a fixed 42-byte NFA field: the tag is
// copied whole (NUL excluded), the tail is zero-padded, and tags longer
// than the field are rejected at compile time. This replaces the raw
// memcpy(field, "tag", 42) pattern whose literal lengths silently
// under-ran the field (reading past the literal — the global-buffer-
// overflow Clang/ASan flagged in CI) or over-ran it.
template <size_t N, size_t M>
inline void set_nfa_field(uint8_t (&dst)[N], const char (&src)[M]) {
    static_assert(M - 1 <= N, "tag does not fit the fixed NFA field");
    constexpr size_t len = M - 1; // exclude the terminating NUL
    std::memcpy(dst, src, len);
    std::memset(dst + len, 0, N - len);
}

template <size_t N, size_t M>
inline void set_nfa_field(std::array<uint8_t, N>& dst, const char (&src)[M]) {
    static_assert(M - 1 <= N, "tag does not fit the fixed NFA field");
    constexpr size_t len = M - 1;
    std::memcpy(dst.data(), src, len);
    std::memset(dst.data() + len, 0, N - len);
}

// ── Constants ────────────────────────────────────────────────────────────────

inline constexpr uint32_t BLOCK_MAGIC        = 0x58564336; // "VXC6" little-endian
inline constexpr size_t   BLOCK_SIZE_BYTES   = 65536;      // exactly 64 KB
inline constexpr size_t   HEADER_SIZE_BYTES  = 472;
inline constexpr size_t   TX_SIZE_BYTES      = 112;
inline constexpr size_t   MAX_TX_PER_BLOCK   = 580;
// NOTE: spec said 88 B padding, but 472 + 580*112 + 88 = 65520 ≠ 65536.
// Exactly 580 transactions of 112 B in a fixed 64 KB frame requires 104 B padding.
inline constexpr size_t   PADDING_SIZE_BYTES = 104;
// NOTE (external review round 5): the tail has NO free bytes — vm_state_root
// (65432..65463), vm_gas_used (65464..65471), pogw_nonce (65472..65479) and
// vm_bytecode (65480..65535) occupy all 104 of them. The GQC aggregate is
// therefore NOT stamped into the frame (that would overwrite consensus
// metadata); it lives in a versioned sidecar record beside the ledger file
// (see storage::BlockStore::stamp_gqc).

static_assert(HEADER_SIZE_BYTES + MAX_TX_PER_BLOCK * TX_SIZE_BYTES + PADDING_SIZE_BYTES == BLOCK_SIZE_BYTES,
              "Block layout must be exactly 64 KB");

// True byte-level packing: alignas(1) alone does NOT remove inter-member padding
// on GCC — uint64_t would still be aligned to offset 8. Packed layout matches
// the on-disk spec offsets (block_height at 0x004, tx_count at 0x1D4, etc.).
#if defined(__GNUC__) || defined(__clang__)
#define VX_PACKED __attribute__((packed))
#else
#define VX_PACKED
#endif

// ── BlockHeader (472 bytes, no alignment padding) ────────────────────────────

struct alignas(1) VX_PACKED BlockHeader {
    uint32_t magic;                          // 0x000  4B   "VXC6"
    uint64_t block_height;                   // 0x004  8B
    uint8_t  prev_block_hash[32];            // 0x00C 32B
    uint8_t  merkle_root[32];                // 0x02C 32B
    uint64_t timestamp;                      // 0x04C  8B
    uint8_t  attractor_coords[384];          // 0x054 384B  X(128) || Y(128) || Z(128)
    uint32_t tx_count;                       // 0x1D4  4B

    bool is_valid_magic() const noexcept { return magic == BLOCK_MAGIC; }
};

static_assert(sizeof(BlockHeader) == HEADER_SIZE_BYTES, "BlockHeader must be 472 bytes");

// ── Transaction (112 bytes, no alignment padding) ───────────────────────────
// Upgraded V2 layout with replay protection (nonce), fee market (TDI burn),
// and backward compatibility for Genesis v1 transactions (amount_hi as fee/nonce flags)

struct alignas(1) VX_PACKED Transaction {
    uint8_t  sender_nfa[42];                 // 42B  base address without NFA_V6_ prefix
    uint8_t  receiver_nfa[42];               // 42B
    uint8_t  amount[8];                      // 8B   uint64_t LE atomics (up to 184.4B VX)
    uint8_t  fee[4];                         // 4B   uint32_t LE micro-VX fee units
    uint8_t  nonce[4];                       // 4B   uint32_t LE per-sender anti-replay counter
    uint8_t  cocoon_proof[12];               // 12B  keyed ARX+Galois tag bound to all fields
};

static_assert(sizeof(Transaction) == TX_SIZE_BYTES, "Transaction must be 112 bytes");

// Helper to get amount as uint64_t (little-endian)
inline uint64_t tx_amount(const Transaction& tx) noexcept {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | tx.amount[i];
    return v;
}

// Helper to get fee as uint32_t (little-endian)
inline uint32_t tx_fee(const Transaction& tx) noexcept {
    uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | tx.fee[i];
    return v;
}

// Helper to get nonce as uint32_t (little-endian)
inline uint32_t tx_nonce(const Transaction& tx) noexcept {
    uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | tx.nonce[i];
    return v;
}

// Helper to set amount (uint64_t, little-endian)
inline void tx_set_amount(Transaction& tx, uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) { tx.amount[i] = static_cast<uint8_t>(v & 0xFF); v >>= 8; }
}

// Helper to set fee (uint32_t, little-endian)
inline void tx_set_fee(Transaction& tx, uint32_t v) noexcept {
    for (int i = 0; i < 4; ++i) { tx.fee[i] = static_cast<uint8_t>(v & 0xFF); v >>= 8; }
}

// Helper to set nonce (uint32_t, little-endian)
inline void tx_set_nonce(Transaction& tx, uint32_t v) noexcept {
    for (int i = 0; i < 4; ++i) { tx.nonce[i] = static_cast<uint8_t>(v & 0xFF); v >>= 8; }
}

// Check if this is a Genesis v1 transaction (fee == 0 and nonce == 0).
// NOTE: this shape alone proves nothing about origin — consumers must
// scope the legacy exemption (see LedgerState::apply_block); a regular
// user transaction with fee=0/nonce=0 is NOT a genesis transaction.
inline bool is_genesis_v1_tx(const Transaction& tx) noexcept {
    for (int i = 0; i < 4; ++i) if (tx.fee[i] != 0 || tx.nonce[i] != 0) return false;
    return true;
}

// Merkle commitment: see the declarations after RawBlock below.

// ── VortexFrameTail (104 bytes, replaces padding) ───────────────────────────

struct alignas(1) VX_PACKED VortexFrameTail {
    uint8_t  vm_state_root[32];              // 32B
    uint64_t vm_gas_used;                    // 8B
    uint64_t pogw_nonce;                     // 8B
    uint8_t  vm_bytecode[56];                // 56B
};

static_assert(sizeof(VortexFrameTail) == PADDING_SIZE_BYTES, "VortexFrameTail must be 104 bytes");

// ── Raw 64 KB Block Frame ───────────────────────────────────────────────────

struct alignas(1) RawBlock {
    BlockHeader header;
    Transaction transactions[MAX_TX_PER_BLOCK];
    VortexFrameTail tail;
};

static_assert(sizeof(RawBlock) == BLOCK_SIZE_BYTES, "RawBlock must be exactly 65536 bytes");

// Tail field offsets are consensus layout facts (external review round 5):
// every consumer of the tail must be able to prove where each field sits.
static_assert(offsetof(RawBlock, tail) == 65432, "tail must start at 65432");
static_assert(offsetof(RawBlock, tail.vm_state_root) == 65432, "vm_state_root at 65432");
static_assert(offsetof(RawBlock, tail.vm_gas_used) == 65464, "vm_gas_used at 65464");
static_assert(offsetof(RawBlock, tail.pogw_nonce) == 65472, "pogw_nonce at 65472");
static_assert(offsetof(RawBlock, tail.vm_bytecode) == 65480, "vm_bytecode at 65480");

// Merkle commitment: recompute from the block body alone and compare
// against the header field. External review P1: the field existed but
// was verified nowhere on intake.
void compute_block_merkle(const RawBlock& raw, uint8_t out[32]) noexcept;
bool verify_block_merkle(const RawBlock& raw) noexcept;

// ── Common aliases ───────────────────────────────────────────────────────────

using BlockFrame = std::array<uint8_t, BLOCK_SIZE_BYTES>; // raw on-disk 64 KB frame
using Address    = std::array<uint8_t, 42>;               // NFA payload without prefix

// ── PQ-bound addresses (BACKLOG 0.7) ─────────────────────────────────────────

/**
 * @brief A user address is spendable only when bound to a post-quantum key.
 * Two binding sources exist:
 *   1. Self-certifying: the address itself commits a PQ root — the payload
 *      is "PQA" followed by 39 base64url characters of
 *      Sponge("VXPQADDRV1" || root), so holding the key IS holding the
 *      address; no registration transaction or trusted table is needed.
 *   2. Protocol seed table: genesis-era allocations (the canonical genesis
 *      receiver, the demo addresses) are bound in ledger state to fixed
 *      roots — see genesis.hpp pq_seed_bindings().
 * Any other user address is rejected by the ledger's apply rules: the
 * keyless Tier-2 fallback is removed from consensus acceptance.
 */
bool is_pq_address(const Address& a) noexcept;
void derive_pq_address(const uint8_t root[32], uint8_t out_addr[42]) noexcept;

/**
 * @brief Strict PQ authorization check for one transaction (the only
 * acceptance path for user senders since the keyless tier was removed).
 * Looks up the witness by canonical message digest, optionally compares the
 * witness's committed XMSS root against the sender's bound root (the caller
 * passes nullptr for a self-certifying address — the caller then re-derives
 * the address from the returned witness's root itself), and runs the full
 * WOTS+/XMSS + anchor verification. Every rejection reason is written to
 * *error when non-null.
 */
bool verify_pq_witness(const Transaction& tx,
                       const std::array<uint8_t, 32>* expected_root,
                       vx::crypto::pq::PqSignatureWitness* out_witness,
                       std::string* error = nullptr) noexcept;

inline Address tx_address(const uint8_t raw[42]) noexcept {
    Address a;
    std::memcpy(a.data(), raw, 42);
    return a;
}

/**
 * @brief Computes the 32-byte header commitment (prev_block_hash binding).
 * Production: replace with BLAKE3-256. Here: deterministic XOR-rotate fold
 * consistent with the Merkle hashing in block.cpp.
 */
void hash_header(const BlockHeader& header, uint8_t out[32]) noexcept;

/**
 * @brief Full consensus commitment over a block frame: header AND tail.
 * External review round 5: hash_header covered only the 472-byte header,
 * leaving the tail's vm_state_root / vm_gas_used / pogw_nonce / vm_bytecode
 * outside the commitment — two frames differing only in their tail (e.g. a
 * mutated PoGW nonce) shared one tip hash. Chain binding (tip_hash) and the
 * RPC block-hash fields use hash_block; hash_header remains for header-only
 * diagnostics.
 */
void hash_block(const RawBlock& raw, uint8_t out[32]) noexcept;

// ── PoGW work: one definition for miner and intake gate ─────────────────────

/// Default live-intake PoGW difficulty: required leading zero bits of the
/// full-frame VortexSponge256 commitment. Dev-mode value matching the miner's
/// ASERT base difficulty; dynamic retargeting is BACKLOG 0.6 follow-up.
inline constexpr uint64_t DEFAULT_POGW_DIFFICULTY_BITS = 16;

/// PoGW target check, single source of truth (BACKLOG 0.9): the miner's
/// success condition and the intake gate both call this, so the definition
/// of "enough work" can never drift between producer and verifier. The hash
/// covers the whole 65536-byte frame including the pogw_nonce field.
bool pogw_meets_target(const uint8_t* frame65536, uint64_t difficulty_bits) noexcept;

/// Finds the smallest pogw_nonce whose full-frame hash meets the target.
/// Writes each candidate into the frame before hashing. Returns false when
/// max_attempts is exhausted (the frame is left at the last tried nonce).
/// Every block producer outside the background miner (RPC transfer/mine
/// path, demo) seals through this, so all produced blocks carry real work.
bool seal_pogw_nonce(BlockFrame& frame, uint64_t difficulty_bits,
                     uint64_t max_attempts = 1ULL << 26) noexcept;

// ── Single intake gate (BACKLOG 0.9) ─────────────────────────────────────────

/// Everything a verifier needs to judge one candidate block against the
/// current chain. Built by the caller from store tip + wall clock; the gate
/// itself is stateless.
struct BlockIntakeContext {
    uint64_t expected_height;
    uint8_t  expected_prev_hash[32];
    uint64_t prev_timestamp;   // tip's timestamp (genesis ts for height 1)
    uint64_t now_unix;         // caller's wall clock
    uint64_t difficulty_bits;  // required leading zero bits of the full-frame hash
};

/**
 * @brief The one consensus gate every intake path runs (BACKLOG 0.9).
 *
 * Checks, in cheap-to-expensive order: frame magic, height == expected,
 * prev_block_hash binding to the current tip, tx_count bound, merkle
 * commitment recomputed from the body, timestamp monotonicity
 * (ts >= prev_ts) and sanity (ts <= now + 300s), and finally PoGW work
 * (full-frame hash leading zero bits >= difficulty_bits). Returning true
 * means the block may be appended and applied; every rejection reason is
 * written to *error when non-null. The recovery/reopen path runs the
 * deterministic subset (magic, height, tx_count, merkle) via
 * BlockStore::validate_region — time-dependent checks are meaningless
 * against historical blocks.
 */
bool validate_block(const RawBlock& raw, const BlockIntakeContext& ctx,
                    std::string* error = nullptr) noexcept;

// ── Coinbase chain-position binding (BACKLOG 0.6 remainder, closed) ─────────

/**
 * @brief The ONLY valid cocoon_proof for a MINER_ coinbase:
 *        trunc12(Sponge("VX_COINBASE_BIND_V1" || receiver[42] || height(8 LE)
 *        || prev_tip_hash[32])).
 * The binding commits the emission to the exact chain position: a coinbase
 * copied from one fork cannot be replayed on a competing fork at the same
 * height (different prev tip) or shifted to another height. The keyless
 * Tier-2 digest no longer authorizes coinbases.
 */
void coinbase_binding(uint8_t out[12], const Address& receiver, uint64_t height,
                      const uint8_t prev_tip_hash[32]) noexcept;
void set_coinbase_binding(Transaction& tx, uint64_t height,
                          const uint8_t prev_tip_hash[32]) noexcept;

// ── Block View (zero-copy over mmap'd or in-memory buffer) ──────────────────

class BlockView {
public:
    explicit BlockView(std::span<const uint8_t, BLOCK_SIZE_BYTES> data) noexcept
        : raw_(reinterpret_cast<const RawBlock*>(data.data())) {}

    const BlockHeader& header() const noexcept { return raw_->header; }

    uint32_t tx_count() const noexcept { return raw_->header.tx_count; }

    const Transaction& tx(uint32_t index) const noexcept {
        return raw_->transactions[index];
    }

    std::span<const Transaction> transactions() const noexcept {
        return {raw_->transactions, raw_->header.tx_count};
    }

    bool valid_magic() const noexcept { return raw_->header.is_valid_magic(); }

    std::span<const uint8_t, BLOCK_SIZE_BYTES> bytes() const noexcept {
        return std::span<const uint8_t, BLOCK_SIZE_BYTES>(
            reinterpret_cast<const uint8_t*>(raw_), BLOCK_SIZE_BYTES);
    }

private:
    const RawBlock* raw_;
};

// ── Block Builder (constructs a 64 KB frame in memory) ──────────────────────

class BlockBuilder {
public:
    BlockBuilder() noexcept { std::memset(&block_, 0, sizeof(block_)); block_.header.magic = BLOCK_MAGIC; }

    void set_height(uint64_t h) noexcept { block_.header.block_height = h; }
    void set_timestamp(uint64_t ts) noexcept { block_.header.timestamp = ts; }
    void set_prev_hash(const uint8_t hash[32]) noexcept { std::memcpy(block_.header.prev_block_hash, hash, 32); }
    void set_attractor_coords(const uint8_t coords[384]) noexcept { std::memcpy(block_.header.attractor_coords, coords, 384); }

    bool add_transaction(const Transaction& tx) noexcept {
        if (block_.header.tx_count >= MAX_TX_PER_BLOCK) return false;
        block_.transactions[block_.header.tx_count++] = tx;
        return true;
    }

    void finalize() noexcept {
        // Zero tail is already zeroed by constructor / memset
        compute_merkle_root();
    }

    void set_nonce(uint64_t nonce) noexcept { block_.tail.pogw_nonce = nonce; }
    void set_state_root(const uint8_t root[32]) noexcept { std::memcpy(block_.tail.vm_state_root, root, 32); }

    const RawBlock& raw() const noexcept { return block_; }
    std::span<const uint8_t, BLOCK_SIZE_BYTES> bytes() const noexcept {
        return std::span<const uint8_t, BLOCK_SIZE_BYTES>(
            reinterpret_cast<const uint8_t*>(&block_), BLOCK_SIZE_BYTES);
    }

    RawBlock& get_raw_non_const() noexcept { return block_; }

private:
    void compute_merkle_root() noexcept;
    RawBlock block_;
};

} // namespace vx::blockchain

