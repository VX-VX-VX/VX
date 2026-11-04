#pragma once
// -----------------------------------------------------------------------------
// Shared deterministic shaping helpers for the libFuzzer targets.
//
// Every value the harnesses derive is a pure function of the input bytes, so
// libFuzzer mutations move every shaped field (heights, hashes, amounts,
// nonces) instead of shooting blind. No sockets, no disk I/O per input, no
// environment paths.
// -----------------------------------------------------------------------------
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/state/ledger_state.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <ctime>

namespace vxfuzz {

using vx::blockchain::Address;
using vx::blockchain::BlockBuilder;
using vx::blockchain::BlockFrame;
using vx::blockchain::BlockIntakeContext;
using vx::blockchain::BlockView;
using vx::blockchain::RawBlock;
using vx::blockchain::Transaction;

// -- Deterministic cyclic bit reader -----------------------------------------
// Reads wrap cyclically over the input, so a 2-byte corpus entry still shapes
// every field of a 64 KiB frame while remaining a pure function of the bytes.
class BitStream {
public:
    BitStream(const uint8_t* d, size_t n) : d_(d), n_(n) {}
    uint8_t u8() { return n_ == 0 ? 0 : d_[o_++ % n_]; }
    uint32_t u32() {
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(u8()) << (8 * i);
        return v;
    }
    uint64_t u64() {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(u8()) << (8 * i);
        return v;
    }
    void bytes(uint8_t* out, size_t k) {
        for (size_t i = 0; i < k; ++i) out[i] = u8();
    }

private:
    const uint8_t* d_;
    size_t n_;
    size_t o_ = 0;
};

// -- Genesis anchor -----------------------------------------------------------
// The deterministic frame #0, built once per process, with its full-frame
// commitment (hash_block: header AND tail) and timestamp -- exactly the values
// a real node derives at boot and every downstream gate compares against.
struct ChainAnchor {
    BlockFrame genesis{};
    uint8_t tip_hash[32]{};
    uint64_t genesis_ts = 0;

    ChainAnchor() {
        genesis = vx::blockchain::build_genesis_frame();
        const auto* raw = reinterpret_cast<const RawBlock*>(genesis.data());
        vx::blockchain::hash_block(*raw, tip_hash);
        genesis_ts = raw->header.timestamp;
    }
};

inline const ChainAnchor& anchor() {
    static ChainAnchor a;
    return a;
}

// Applies frame #0 to a fresh ledger state (the genesis replay every node
// runs before height 1 can be judged). Cheap: one coinbase transaction.
inline bool apply_genesis(vx::state::LedgerState& ledger) {
    BlockView view{std::span<const uint8_t, 65536>(anchor().genesis.data(), 65536)};
    return ledger.apply_block(view).ok;
}

// -- PQ accounts --------------------------------------------------------------
struct PqAccount {
    std::array<uint8_t, 32> sk{};
    std::array<uint8_t, 32> root{};
    Address addr{};
};

// Self-certifying account: sk = Sponge(tag), root = XMSS(sk), and the address
// commits its own root ("PQA..." payload), so holding the key IS holding the
// address (BACKLOG 0.7). Same derivation the test suite pins.
inline PqAccount make_pq_account(const uint8_t* tag, size_t len) {
    PqAccount acc;
    vx::blockchain::VortexSponge256::compute(tag, len, acc.sk.data());
    const auto pub = vx::crypto::pq::pub_seed_from_sk(acc.sk);
    acc.root = vx::crypto::pq::xmss_root(acc.sk, pub);
    vx::blockchain::derive_pq_address(acc.root.data(), acc.addr.data());
    return acc;
}

// The pinned demo spender: a BOUND (not self-certifying) address -- the
// binding table maps the attractor-derived Address #2 payload to the root of
// the public demo key, and the one-time GENESIS_2 mint pays exactly this
// address at height 1.
inline const PqAccount& demo_spender() {
    static const PqAccount acc = [] {
        PqAccount a = make_pq_account(reinterpret_cast<const uint8_t*>("VX_DEMO_SPENDER_SK_V1"), 21);
        a.addr = vx::blockchain::genesis2_mint_receiver_payload();
        return a;
    }();
    return acc;
}

// Signs with the account's PQ key and registers the witness in the
// PqWitnessRegistry (the same call a real client makes).
inline bool pq_sign(Transaction& tx, const std::array<uint8_t, 32>& sk) {
    return vx::crypto::pq::pq_sign_transaction(tx, sk);
}

// -- Transaction shaping ------------------------------------------------------
inline Transaction make_tx(const Address& sender, const Address& receiver,
                           uint64_t amount, uint32_t fee, uint32_t nonce) {
    Transaction tx{};
    std::memcpy(tx.sender_nfa, sender.data(), 42);
    std::memcpy(tx.receiver_nfa, receiver.data(), 42);
    vx::blockchain::tx_set_amount(tx, amount);
    vx::blockchain::tx_set_fee(tx, fee);
    vx::blockchain::tx_set_nonce(tx, nonce);
    return tx;
}

// Decodes one 112-byte transaction straight from input bytes (cyclic fill):
// every field, including the cocoon_proof, is input-driven.
inline Transaction decode_tx(BitStream& bs) {
    Transaction tx{};
    bs.bytes(tx.sender_nfa, 42);
    bs.bytes(tx.receiver_nfa, 42);
    vx::blockchain::tx_set_amount(tx, bs.u64());
    vx::blockchain::tx_set_fee(tx, bs.u32());
    vx::blockchain::tx_set_nonce(tx, bs.u32());
    bs.bytes(tx.cocoon_proof, 12);
    return tx;
}

// -- Single intake gate + state layer, in one step ----------------------------
// Runs validate_block with a caller-supplied live context (the ctx is NEVER
// mirrored from the frame -- expected height/prev come from the caller) and,
// on a pass, applies the frame to the given ledger state.
struct GateOpts {
    uint64_t expected_height = 0;
    const uint8_t* expected_prev = nullptr; // 32 bytes
    uint64_t prev_timestamp = 0;
    uint64_t now_unix = 0;
    uint64_t difficulty_bits = 0;
};

inline bool validate_with_ctx(const RawBlock& raw, const GateOpts& o) {
    BlockIntakeContext ctx{};
    ctx.expected_height = o.expected_height;
    if (o.expected_prev) std::memcpy(ctx.expected_prev_hash, o.expected_prev, 32);
    ctx.prev_timestamp = o.prev_timestamp;
    ctx.now_unix = o.now_unix;
    ctx.difficulty_bits = o.difficulty_bits;
    return vx::blockchain::validate_block(raw, ctx);
}

inline bool validate_then_apply(const RawBlock& raw, const GateOpts& o,
                                vx::state::LedgerState& ledger) {
    if (!validate_with_ctx(raw, o)) return false;
    BlockView view{std::span<const uint8_t, 65536>(
        reinterpret_cast<const uint8_t*>(&raw), 65536)};
    return ledger.apply_block(view).ok;
}

} // namespace vxfuzz
