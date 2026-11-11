#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/crypto/pq_signature.hpp"
#include <array>
#include <cstring>
#include <iostream>
#include <vector>

namespace vx::blockchain {

void hash_header(const BlockHeader& header, uint8_t out[32]) noexcept {
    VortexSponge256::compute(reinterpret_cast<const uint8_t*>(&header), HEADER_SIZE_BYTES, out);
}

void hash_block(const RawBlock& raw, uint8_t out[32]) noexcept {
    // Full consensus commitment: header (504 B in VXC7, including the
    // witness_merkle_root - BACKLOG 2.11) AND tail (104 B). The tail
    // carries vm_state_root, vm_gas_used, pogw_nonce and vm_bytecode — all
    // consensus-critical, none of them covered by the header alone
    // (external review round 5: a mutated pogw_nonce used to leave the
    // block hash unchanged).
    VortexSponge256 sponge;
    sponge.absorb(reinterpret_cast<const uint8_t*>(&raw.header), HEADER_SIZE_BYTES);
    sponge.absorb(reinterpret_cast<const uint8_t*>(&raw.tail), PADDING_SIZE_BYTES);
    sponge.finalize(out);
}

// ── PoGW work + intake gate (BACKLOG 0.9) ────────────────────────────────────

bool pogw_meets_target(const uint8_t* frame65536, uint64_t difficulty_bits) noexcept {
    if (difficulty_bits == 0) return true;
    if (difficulty_bits > 256) return false;
    uint8_t hash[32];
    VortexSponge256::compute(frame65536, BLOCK_SIZE_BYTES, hash);
    uint64_t zeros = 0;
    for (size_t i = 0; i < sizeof(hash); ++i) {
        if (hash[i] != 0) {
            uint8_t b = hash[i];
            while ((b & 0x80) == 0) { ++zeros; b <<= 1; }
            break;
        }
        zeros += 8;
    }
    return zeros >= difficulty_bits;
}

bool seal_pogw_nonce(BlockFrame& frame, uint64_t difficulty_bits, uint64_t max_attempts) noexcept {
    if (difficulty_bits == 0) return true;
    auto* raw = reinterpret_cast<RawBlock*>(frame.data());
    for (uint64_t nonce = 0; nonce < max_attempts; ++nonce) {
        raw->tail.pogw_nonce = nonce;
        if (pogw_meets_target(frame.data(), difficulty_bits)) return true;
    }
    return false;
}

bool validate_block(const RawBlock& raw, const BlockIntakeContext& ctx,
                    std::string* error) noexcept {
    auto fail = [&](const char* why) {
        if (error) *error = why;
        return false;
    };

    // 1. Frame magic — the cheapest rejection first. The message names the
    //    version a peer offered so an operator sees VXC6 vs corruption.
    if (raw.header.is_v1_magic())
        return fail("VXC6 frame refused: pre-2.11 format without a witness commitment");
    if (raw.header.magic != BLOCK_MAGIC) return fail("bad frame magic");

    // 2. Chain position: the block must extend the current tip exactly.
    if (raw.header.block_height != ctx.expected_height) return fail("height != tip + 1");

    // 3. Chain binding: prev_block_hash must commit the current tip
    //    (full-frame commitment, header AND tail).
    if (std::memcmp(raw.header.prev_block_hash, ctx.expected_prev_hash, 32) != 0)
        return fail("prev_block_hash does not bind the current tip");

    // 4. Body bound: an oversized tx_count would poison the ledger file
    //    permanently (recovery then fails on reopen).
    if (raw.header.tx_count > MAX_TX_PER_BLOCK) return fail("tx_count exceeds MAX_TX_PER_BLOCK");

    // 5. Merkle commitment recomputed from the body alone.
    if (!verify_block_merkle(raw)) return fail("merkle_root does not commit the block body");

    // 5b. Witness commitment structural check (BACKLOG 2.11): a block with
    //     NO user transactions has a deterministically empty witness set,
    //     so its header must commit exactly the empty constant - and the
    //     inverse holds without any registry access: every user transaction
    //     is resolved to exactly one canonical witness before a block may
    //     apply, so a user-tx block committing the empty constant is a lie
    //     on its face. A user-tx block's full recomputation runs in
    //     LedgerState::apply_block, which holds every verifying witness.
    {
        uint32_t user_txs = 0;
        const uint32_t cnt =
            raw.header.tx_count > MAX_TX_PER_BLOCK ? MAX_TX_PER_BLOCK : raw.header.tx_count;
        for (uint32_t i = 0; i < cnt; ++i)
            if (!is_system_sender(tx_address(raw.transactions[i].sender_nfa)))
                ++user_txs;
        const bool empty_root =
            std::memcmp(raw.header.witness_merkle_root, witness_merkle_empty_root(), 32) == 0;
        if (user_txs == 0 && !empty_root)
            return fail("witness_merkle_root is not the empty constant on a witness-free block");
        if (user_txs > 0 && empty_root)
            return fail("witness_merkle_root is the empty constant on a block with user "
                        "transactions");
    }

    // 6. Timestamp: monotonic against the tip, not far in the future.
    //    (Genesis never passes through this gate — the store seeds it
    //    directly — so height 0 needs no special case.)
    if (raw.header.timestamp < ctx.prev_timestamp) return fail("timestamp older than the tip");
    if (raw.header.timestamp > ctx.now_unix + 300) return fail("timestamp too far in the future");

    // 7. PoGW: the full-frame commitment must carry the required work.
    //    This is the expensive check, so it runs last.
    if (!pogw_meets_target(reinterpret_cast<const uint8_t*>(&raw), ctx.difficulty_bits))
        return fail("insufficient PoGW work for the current difficulty");

    if (error) error->clear();
    return true;
}

// ── Coinbase chain-position binding (BACKLOG 0.6 remainder, closed) ─────────

void coinbase_binding(uint8_t out[12], const Address& receiver, uint64_t height,
                      const uint8_t prev_tip_hash[32]) noexcept {
    uint8_t buf[42 + 8 + 32];
    std::memcpy(buf, receiver.data(), 42);
    for (int i = 0; i < 8; ++i) buf[42 + i] = static_cast<uint8_t>((height >> (i * 8)) & 0xFF);
    std::memcpy(buf + 50, prev_tip_hash, 32);
    uint8_t full[32];
    VortexSponge256::compute(buf, sizeof(buf), full);
    std::memcpy(out, full, 12);
}

void set_coinbase_binding(Transaction& tx, uint64_t height,
                          const uint8_t prev_tip_hash[32]) noexcept {
    coinbase_binding(tx.cocoon_proof, tx_address(tx.receiver_nfa), height, prev_tip_hash);
}

// ── Merkle root logic using Sponge ──────────────────────────────────────────

void hash_tx(const Transaction& tx, uint8_t out[32]) noexcept {
    VortexSponge256::compute(reinterpret_cast<const uint8_t*>(&tx), TX_SIZE_BYTES, out);
}

static void hash_pair(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) noexcept {
    uint8_t buffer[64];
    std::memcpy(buffer, left, 32);
    std::memcpy(buffer + 32, right, 32);
    VortexSponge256::compute(buffer, 64, out);
}

void BlockBuilder::compute_merkle_root() noexcept {
    compute_block_merkle(block_, block_.header.merkle_root);
}

void BlockBuilder::compute_witness_root() noexcept {
    compute_witness_merkle_root(bindings_.data(), bindings_.size(),
                                block_.header.witness_merkle_root);
}

size_t BlockBuilder::bind_canonical_witnesses(BoundRootOf bound_root_of) {
    const size_t before = bindings_.size();
    for (uint32_t i = 0; i < block_.header.tx_count; ++i) {
        const Address sender = tx_address(block_.transactions[i].sender_nfa);
        if (is_system_sender(sender))
            continue;
        std::array<uint8_t, 32> root{};
        if (!consensus_witness_root(block_.transactions[i], bound_root_of, root))
            continue;
        WitnessBinding b;
        b.tx_index = i;
        b.sender = sender;
        b.pq_root = root;
        bindings_.push_back(b);
    }
    return bindings_.size() - before;
}

void compute_block_merkle(const RawBlock& raw, uint8_t out[32]) noexcept {
    uint32_t count = raw.header.tx_count;
    // Structural cap: the fixed frame cannot hold more than MAX_TX_PER_BLOCK
    // transactions. add_transaction() enforces this on the way in; the clamp
    // keeps the hash loop in-bounds even if the invariant were ever broken.
    if (count > MAX_TX_PER_BLOCK) count = MAX_TX_PER_BLOCK;
    if (count == 0) {
        std::memset(out, 0, 32);
        return;
    }

    uint8_t hashes[MAX_TX_PER_BLOCK][32];
    for (uint32_t i = 0; i < count; ++i) {
        hash_tx(raw.transactions[i], hashes[i]);
    }

    uint32_t level_size = count;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1) / 2;
        for (uint32_t i = 0; i < next_size; ++i) {
            uint32_t left = i * 2;
            uint32_t right = (left + 1 < level_size) ? left + 1 : left;
            hash_pair(hashes[left], hashes[right], hashes[i]);
        }
        level_size = next_size;
    }
    std::memcpy(out, hashes[0], 32);
}

bool verify_block_merkle(const RawBlock& raw) noexcept {
    // Independent recomputation: the header merkle field is a commitment
    // only if a verifier can rebuild it from the block body alone
    // (external review P1: the field existed but was checked nowhere).
    uint8_t expect[32];
    compute_block_merkle(raw, expect);
    return std::memcmp(expect, raw.header.merkle_root, 32) == 0;
}

// ── Witness merkle commitment (BACKLOG 2.11) ─────────────────────────────────

bool is_system_sender(const Address &a) noexcept {
    // Same classification apply_block uses: GENESIS mints and MINER_
    // coinbases are protocol senders and carry no PQ witness.
    return std::memcmp(a.data(), "GENESIS", 7) == 0 || std::memcmp(a.data(), "MINER_", 6) == 0;
}

const uint8_t *witness_merkle_empty_root() noexcept {
    static const std::array<uint8_t, 32> empty = [] {
        std::array<uint8_t, 32> d{};
        VortexSponge256::compute(reinterpret_cast<const uint8_t *>("VXWMRE1"), 7, d.data());
        return d;
    }();
    return empty.data();
}

static void witness_hash_leaf(uint32_t tx_index, const uint8_t sender[42],
                              const uint8_t pq_root[32], uint8_t out[32]) noexcept {
    uint8_t buf[7 + 4 + 42 + 32];
    std::memcpy(buf, "VXWMRL1", 7);
    for (int i = 0; i < 4; ++i)
        buf[7 + i] = static_cast<uint8_t>((tx_index >> (i * 8)) & 0xFF);
    std::memcpy(buf + 11, sender, 42);
    std::memcpy(buf + 53, pq_root, 32);
    VortexSponge256::compute(buf, sizeof(buf), out);
}

static void witness_hash_node(const uint8_t left[32], const uint8_t right[32],
                              uint8_t out[32]) noexcept {
    uint8_t buf[7 + 64];
    std::memcpy(buf, "VXWMRN1", 7);
    std::memcpy(buf + 7, left, 32);
    std::memcpy(buf + 39, right, 32);
    VortexSponge256::compute(buf, sizeof(buf), out);
}

void compute_witness_merkle_root(const WitnessBinding *bindings, size_t n,
                                 uint8_t out[32]) noexcept {
    if (n == 0 || bindings == nullptr) {
        std::memcpy(out, witness_merkle_empty_root(), 32);
        return;
    }
    std::vector<std::array<uint8_t, 32>> level(n);
    for (size_t i = 0; i < n; ++i)
        witness_hash_leaf(bindings[i].tx_index, bindings[i].sender.data(),
                          bindings[i].pq_root.data(), level[i].data());
    while (level.size() > 1) {
        std::vector<std::array<uint8_t, 32>> next((level.size() + 1) / 2);
        for (size_t i = 0; i < next.size(); ++i) {
            const size_t l = i * 2;
            const size_t r = (l + 1 < level.size()) ? l + 1 : l;
            witness_hash_node(level[l].data(), level[r].data(), next[i].data());
        }
        level = std::move(next);
    }
    std::memcpy(out, level[0].data(), 32);
}

WitnessRootStatus verify_witness_merkle(const RawBlock &raw, BoundRootOf bound_root_of) noexcept {
    // Recompute the tree from the CANONICAL key identity of every user tx
    // (consensus_witness_root), verified against the registry. The
    // canonical selection is arrival-order independent, so two nodes
    // holding the same witnesses in different orders compute the same tree.
    std::vector<WitnessBinding> bindings;
    const uint32_t count =
        raw.header.tx_count > MAX_TX_PER_BLOCK ? MAX_TX_PER_BLOCK : raw.header.tx_count;
    for (uint32_t i = 0; i < count; ++i) {
        const Address sender = tx_address(raw.transactions[i].sender_nfa);
        if (is_system_sender(sender))
            continue;
        std::array<uint8_t, 32> root{};
        if (!consensus_witness_root(raw.transactions[i], bound_root_of, root))
            return WitnessRootStatus::MISSING_WITNESS;
        WitnessBinding b;
        b.tx_index = i;
        b.sender = sender;
        b.pq_root = root;
        bindings.push_back(b);
    }
    uint8_t expect[32];
    compute_witness_merkle_root(bindings.data(), bindings.size(), expect);
    if (std::memcmp(expect, raw.header.witness_merkle_root, 32) != 0)
        return WitnessRootStatus::MISMATCH;
    return WitnessRootStatus::MATCH;
}

bool consensus_witness_root(const Transaction &tx, BoundRootOf bound_root_of,
                            std::array<uint8_t, 32> &out_root) noexcept {
    const Address sender = tx_address(tx.sender_nfa);
    const std::function<bool(const Address &, std::array<uint8_t, 32> &)> oracle = bound_root_of;

    // 1. Ledger-bound root: the address was bound by an accepted block (or
    //    the genesis seed table at boot). The witness must carry exactly it
    //    - or a root the sender's own certified rollover chain walks to
    //    (BACKLOG 1.5), exactly the selection the ledger's verifier runs;
    //    the producer must not bind a root its own node would refuse.
    if (oracle && oracle(sender, out_root)) {
        if (vx::crypto::pq::PqWitnessRegistry::instance().lookup_verifying_with_root(tx,
                                                                                     out_root)) {
            // Retirement (wallet policy, owner sign-off 2026-11-11): a
            // window-0 witness is canonical only while NO certified
            // rotation retires the bound root — the producer must not bind
            // a root its own ledger verifier refuses (LedgerState apply
            // runs the same check).
            std::array<uint8_t, 32> retired_root{};
            uint32_t retired_window = 0;
            if (vx::crypto::pq::PqWitnessRegistry::instance().advance_root_chain(
                    sender.data(), out_root, retired_root, retired_window) &&
                retired_window > 0)
                return false;
            return true;
        }
        std::array<uint8_t, 32> walked{};
        uint32_t walked_window = 0;
        if (vx::crypto::pq::PqWitnessRegistry::instance().advance_root_chain(
                sender.data(), out_root, walked, walked_window) &&
            vx::crypto::pq::PqWitnessRegistry::instance().lookup_verifying_with_root(tx, walked)) {
            out_root = walked;
            return true;
        }
        return false;
    }

    // 2. Genesis seed table: the deterministic protocol bindings every node
    //    computes identically at boot (genesis receiver, demo economy).
    for (const auto &b : pq_seed_bindings()) {
        if (b.addr == sender) {
            // Same retirement rule as the ledger-bound case above (security
            // review P3-1): unreachable on live nodes (the ledger preloads
            // seed bindings into its bound-root table, so seed-table
            // senders hit case 1), kept symmetric for non-ledger oracles.
            std::array<uint8_t, 32> retired_root{};
            uint32_t retired_window = 0;
            if (vx::crypto::pq::PqWitnessRegistry::instance().advance_root_chain(
                    sender.data(), b.root, retired_root, retired_window) &&
                retired_window > 0)
                return false;
            out_root = b.root;
            return vx::crypto::pq::PqWitnessRegistry::instance().lookup_verifying_with_root(
                tx, out_root);
        }
    }

    // 3. Self-certifying PQA: the address commits its own key root, so any
    //    registry candidate that verifies against THIS transaction and
    //    re-derives the sender address pins the canonical root (a second
    //    distinct root re-deriving the same 234-bit payload is a 2^-234
    //    sponge collision, not a design ambiguity).
    if (is_pq_address(sender)) {
        vx::crypto::pq::PqSignatureWitness w;
        if (!vx::crypto::pq::PqWitnessRegistry::instance().lookup_verifying(tx, w))
            return false;
        Address chk{};
        derive_pq_address(w.pq_pubkey_root.data(), chk.data());
        if (chk != sender)
            return false;
        out_root = w.pq_pubkey_root;
        return true;
    }
    return false;
}

// Chain ID for replay protection across networks
// NOTE: a frozen tx-preimage domain constant (the tx digest derivation is
// pinned by the witness vectors) - NOT the frame-format version, which is
// BLOCK_MAGIC above.
inline constexpr uint64_t CHAIN_ID = 0x58564336; // "VXC6"

// ── Transaction Proof System V2 ──────────────────────────────────────────────
// Preimage: sender(42) || receiver(42) || amount(8) || fee(4) || nonce(4) || chain_id(8) = 108 bytes

static void build_tx_preimage(const Transaction& tx, uint8_t out[108]) noexcept {
    std::memcpy(out, tx.sender_nfa, 42);
    std::memcpy(out + 42, tx.receiver_nfa, 42);
    std::memcpy(out + 84, tx.amount, 8);
    std::memcpy(out + 92, tx.fee, 4);
    std::memcpy(out + 96, tx.nonce, 4);
    // Chain ID as 8 bytes LE
    for (int i = 0; i < 8; ++i) {
        out[100 + i] = static_cast<uint8_t>((CHAIN_ID >> (i * 8)) & 0xFF);
    }
}

void sign_transaction(Transaction& tx) noexcept {
    uint8_t preimage[108];
    build_tx_preimage(tx, preimage);

    uint8_t digest[32];
    VortexSponge256::compute(preimage, 108, digest);

    // Cocoon proof is the first 12 bytes of the digest.
    std::memcpy(tx.cocoon_proof, digest, 12);
}

bool verify_transaction_proof(const Transaction& tx) noexcept {
    // ── Tier 1: SegPQ — the sender is backed by a WOTS+/XMSS post-quantum key.
    // A registered sender MUST carry a valid PqSignatureWitness: a MITM that
    // mutates amount/receiver and re-runs the keyless sign_transaction() only
    // recomputes the checksum — it cannot produce the WOTS+ chains (Winternitz
    // checksum barrier) nor match the registered XMSS root.
    if (vx::crypto::pq::PqWitnessRegistry::instance().is_pq_sender(tx.sender_nfa)) {
        const auto msg = vx::crypto::pq::tx_msg_digest(tx);
        vx::crypto::pq::PqSignatureWitness w;
        // Math-audit F7: use the consensus lookup, not the first candidate.
        // An attacker can register a SELF-CONSISTENT witness (own root) for
        // a predictable digest before the honest one arrives; lookup() then
        // hands the attacker's candidate to verification and the honest
        // transaction briefly fails Tier-1 (admission/RPC censoring).
        // lookup_verifying only returns candidates that actually verify
        // against THIS transaction.
        if (!vx::crypto::pq::PqWitnessRegistry::instance().lookup_verifying(tx, w))
            return false;
        return vx::crypto::pq::pq_verify_transaction(tx, w);
    }

    // ── Tier 2: legacy keyless integrity check — SYSTEM SENDERS ONLY.
    // External review demonstrated that this check authorizes anyone (the
    // digest requires no key), so consensus no longer accepts it for user
    // addresses: LedgerState::apply_block routes user senders through
    // verify_pq_witness() and rejects every unbound sender. This path
    // remains only for the protocol's own senders (GENESIS mints, MINER_
    // coinbases) whose guards live in the ledger rules, and for admission
    // pre-filtering outside consensus.
    uint8_t preimage[108];
    build_tx_preimage(tx, preimage);

    uint8_t digest[32];
    VortexSponge256::compute(preimage, 108, digest);

    return std::memcmp(tx.cocoon_proof, digest, 12) == 0;
}

// ── PQ-bound addresses + strict PQ authorization (BACKLOG 0.7) ───────────────

bool is_pq_address(const Address& a) noexcept {
    return std::memcmp(a.data(), "PQA", 3) == 0;
}

void derive_pq_address(const uint8_t root[32], uint8_t out_addr[42]) noexcept {
    // Address payload = "PQA" + 39 base64url chars of
    // Sponge("VXPQADDRV1" || root). 39 chars x 6 bits = 234 bits of the
    // 256-bit digest (the truncation is one-way input, not a security
    // boundary — the root itself is fully committed by the witness).
    std::memcpy(out_addr, "PQA", 3);
    uint8_t buf[42];
    std::memcpy(buf, "VXPQADDRV1", 10);
    std::memcpy(buf + 10, root, 32);
    uint8_t d[32];
    VortexSponge256::compute(buf, sizeof(buf), d);

    static constexpr char kAlpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    uint32_t acc = 0;
    int bits = 0;
    size_t oi = 3;
    for (size_t i = 0; i < sizeof(d) && oi < 42; ++i) {
        acc = (acc << 8) | d[i];
        bits += 8;
        while (bits >= 6 && oi < 42) {
            bits -= 6;
            out_addr[oi++] = static_cast<uint8_t>(kAlpha[(acc >> bits) & 0x3F]);
        }
    }
    while (oi < 42) out_addr[oi++] = static_cast<uint8_t>(kAlpha[0]);
}

bool verify_pq_witness(const Transaction& tx,
                       const std::array<uint8_t, 32>* expected_root,
                       vx::crypto::pq::PqSignatureWitness* out_witness,
                       std::string* error) noexcept {
    auto fail = [&](const char* why) {
        if (error) *error = why;
        return false;
    };

    // Round-7 hardening: the registry is a cache, not an authority. A
    // digest may hold several candidates (an attacker can register a
    // cryptographically valid signature for a digest they predict); the
    // consensus lookup returns only a candidate that passes the FULL
    // WOTS+/XMSS + anchor verification against THIS transaction.
    vx::crypto::pq::PqSignatureWitness w;
    if (!vx::crypto::pq::PqWitnessRegistry::instance().lookup_verifying(tx, w))
        return fail("no PQ witness registered for this transaction");

    if (expected_root && std::memcmp(w.pq_pubkey_root.data(), expected_root->data(), 32) != 0)
        return fail("PQ witness root does not match the sender's bound key");

    if (out_witness) *out_witness = w;
    if (error) error->clear();
    return true;
}

} // namespace vx::blockchain
