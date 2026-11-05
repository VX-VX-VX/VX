#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/pq_signature.hpp"
#include <cstring>
#include <iostream>

namespace vx::blockchain {

void hash_header(const BlockHeader& header, uint8_t out[32]) noexcept {
    VortexSponge256::compute(reinterpret_cast<const uint8_t*>(&header), HEADER_SIZE_BYTES, out);
}

void hash_block(const RawBlock& raw, uint8_t out[32]) noexcept {
    // Full consensus commitment: header (472 B) AND tail (104 B). The tail
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

    // 1. Frame magic — the cheapest rejection first.
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

// Chain ID for replay protection across networks
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
