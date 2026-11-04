// -----------------------------------------------------------------------------
// libFuzzer target: arbitrary bytes against the 64 KiB block-frame surface --
// hostile parse, the single intake gate with LIVE gates 2/3, and the state
// layer behind it.
//
// Layer 1 (always): the raw input padded to one frame and parsed by BlockView
//   (magic, height, count) with bounded transaction accessors, then fed
//   through validate_block with a LIVE intake context (expected height and
//   expected prev hash from separate input bytes, never mirrored from the
//   frame) and the PoGW comparator.
//
// Layer 2 (built frame): a BlockBuilder frame whose height, prev hash,
//   timestamp, work and transactions are all input-shaped, so the merkle root
//   always recomputes (1 / 2 / many transactions). Consistent mode lets the
//   fuzzer make the frame agree with its context; mismatched mode feeds
//   conflicting values. A frame that passes the gate is applied to a fresh
//   genesis-seeded LedgerState, and its transactions go through the mempool
//   with real balances and nonces (TDI dust + pending-state gates).
//
// Layer 3 (Tier-1 PQ deep chain, input-gated to bound signing cost): the
//   pinned height-1 GENESIS_2 mint funds the demo spender; a self-certifying
//   PQ account derived from the input (sk = Sponge(tag), root = XMSS(sk),
//   addr = PQA(payload)) is credited by a witnessed spend, binds on its own
//   first witnessed spend and then spends onward. Hostile variants (a second
//   mint of any shape, a replayed nonce, an overspend, a wrong-root witness)
//   exercise the rejection ladders.
//
// PoGW difficulty is input-derived (data[0] % 33) and HARD-CAPPED at 26
// leading zero bits: the old harness fed the comparator up to 32 bits, and a
// seal at that difficulty is 2^32 sponge passes -- a self-DoS. The capped
// comparator call stays one full-frame pass; the optional sealed-work path
// only runs at <= 4 bits with a bounded nonce search.
//
// Invariant: parsing, validation and application of a hostile frame must
// never crash, hang or read outside the 65536-byte frame.
// -----------------------------------------------------------------------------
#include "harness_util.hpp"
#include "vx/state/mempool.hpp"

#include <cstdint>
#include <cstring>
#include <ctime>

namespace {

using vxfuzz::anchor;
using vxfuzz::BitStream;
using vxfuzz::PqAccount;
using vx::blockchain::Address;
using vx::blockchain::Transaction;
using vxfuzz::BlockFrame;
using vxfuzz::ChainAnchor;

constexpr uint64_t POGW_BITS_CAP = 26; // harness ceiling (the raw byte can pick 32)
constexpr uint64_t SEALABLE_BITS = 4;  // bounded seal search: <= 16 sponge passes

inline uint64_t clamp_pogw_bits(uint64_t raw) {
    return raw > POGW_BITS_CAP ? POGW_BITS_CAP : raw;
}

// Maps an input byte onto interesting height values while staying fully
// input-driven: the "height != tip + 1" rejection must be reachable from
// plain mutations.
inline uint64_t shape_height(uint8_t sel, BitStream& bs) {
    switch (sel % 5) {
    case 0: return 1; // the genesis-only chain's next height
    case 1: return 2; // one past it
    case 2: return 0; // re-announcing genesis
    case 3: return 0xFFFFFFFFFFFFFFFFULL;
    default: return bs.u64();
    }
}

inline uint64_t shape_timestamp(uint8_t sel, BitStream& bs, uint64_t now) {
    switch (sel % 4) {
    case 0: return now;                  // sane: passes the sanity gate
    case 1: return anchor().genesis_ts;  // equal to the tip's timestamp
    case 2: return bs.u64();             // hostile (too old / too new)
    default: return now + 301 + bs.u8(); // just past the +300s sanity window
    }
}

Address tag_address(const char* tag, size_t len) {
    Address a{};
    std::memcpy(a.data(), tag, len);
    return a;
}

// -- Layer 1: hostile structural parse + live-context gate --------------------
void hostile_frame_layer(const uint8_t* data, size_t size, uint64_t pogw_bits) {
    static thread_local std::array<uint8_t, vx::blockchain::BLOCK_SIZE_BYTES> frame{};
    std::memset(frame.data(), 0, frame.size());
    std::memcpy(frame.data(), data, size < frame.size() ? size : frame.size());

    vx::blockchain::BlockView v{
        std::span<const uint8_t, 65536>(frame.data(), frame.size())};
    (void)v.valid_magic();
    (void)v.header().block_height;
    const uint32_t count = v.header().tx_count;
    const uint32_t scan = count > vx::blockchain::MAX_TX_PER_BLOCK
                              ? vx::blockchain::MAX_TX_PER_BLOCK : count;
    for (uint32_t i = 0; i < scan; ++i) {
        const vx::blockchain::Transaction& tx = v.tx(i);
        volatile uint64_t amt = vx::blockchain::tx_amount(tx);
        volatile uint32_t fee = vx::blockchain::tx_fee(tx);
        volatile uint32_t nonce = vx::blockchain::tx_nonce(tx);
        (void)amt; (void)fee; (void)nonce;
        (void)vx::blockchain::verify_transaction_proof(tx);
        (void)vx::blockchain::is_genesis_v1_tx(tx);
    }

    // LIVE intake context over the hostile frame: expected height and prev
    // hash come from the input bytes, never from the frame itself, so the
    // chain-position and chain-binding gates are exercised, not bypassed.
    BitStream bs(data, size);
    bs.u8(); // ctrl byte (already consumed by the caller's parse)
    vxfuzz::GateOpts o;
    o.expected_height = shape_height(bs.u8(), bs);
    uint8_t expected_prev[32];
    bs.bytes(expected_prev, 32);
    o.expected_prev = expected_prev;
    o.prev_timestamp = 0;
    o.now_unix = static_cast<uint64_t>(std::time(nullptr));
    o.difficulty_bits = pogw_bits;
    const auto* raw = reinterpret_cast<const vx::blockchain::RawBlock*>(frame.data());
    (void)vxfuzz::validate_with_ctx(*raw, o);
    // Work comparator with the input-driven, capped difficulty.
    (void)vx::blockchain::pogw_meets_target(frame.data(), pogw_bits);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0;
    BitStream bs(data, size);

    const uint8_t ctrl = bs.u8();
    // PoGW difficulty: input-driven, hard-capped (the old harness let the
    // comparator run at up to 32 bits; a seal at that cost is self-DoS).
    const uint64_t pogw_bits = clamp_pogw_bits(ctrl % 33);
    const uint8_t mode = (ctrl >> 1) & 0x03;
    // Deep PQ chain: mode 3 AND a 1-in-16 gate byte. A real WOTS+/XMSS sign
    // (keygen + chains) costs ~20 ms, so the full Tier-1 chain must stay a
    // small fraction of the executions; the corpus keeps the gate hot.
    const bool deep_pq = (mode == 3) && ((bs.u8() & 0x0F) == 0x07);
    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    // Layer 1 always: the hostile structural surface.
    hostile_frame_layer(data, size, pogw_bits);

    // -- Layer 2: built frame with live gates 2/3 ----------------------------
    // (mode-3 inputs that lost the deep-PQ gate also build frames, so no
    // execution is wasted on layer 1 alone)
    if (mode == 1 || mode == 2 || (mode == 3 && !deep_pq)) {
        vxfuzz::GateOpts o;
        o.expected_height = shape_height(bs.u8(), bs);
        uint8_t expected_prev[32];
        bs.bytes(expected_prev, 32);
        o.expected_prev = expected_prev;
        o.prev_timestamp = (bs.u8() % 3 == 0) ? anchor().genesis_ts : 0;
        o.now_unix = now;
        const uint8_t dsel = bs.u8();
        const bool sealed = (dsel >= 1 && dsel <= SEALABLE_BITS);
        o.difficulty_bits = sealed ? dsel : pogw_bits;

        vx::blockchain::BlockBuilder b;
        // Consistent mode: the frame mirrors the context's chain position.
        // Mismatched mode: deliberately conflicting, still input-derived.
        b.set_height((mode == 1) ? o.expected_height
                                 : o.expected_height + 1 + (bs.u8() & 7));
        uint8_t frame_prev[32];
        std::memcpy(frame_prev, expected_prev, 32);
        if (mode == 2) frame_prev[bs.u8() & 31] ^= static_cast<uint8_t>(bs.u8() | 1);
        b.set_prev_hash(frame_prev);
        b.set_timestamp(shape_timestamp(bs.u8(), bs, now));
        std::array<uint8_t, 384> coords{};
        b.set_attractor_coords(coords.data());
        const uint32_t ntx = bs.u8() % (vx::blockchain::MAX_TX_PER_BLOCK + 1);
        for (uint32_t i = 0; i < ntx; ++i) {
            (void)b.add_transaction(vxfuzz::decode_tx(bs));
        }
        b.finalize(); // the merkle root always recomputes: 1 / 2 / many txs

        if (sealed) {
            // Real work: bounded nonce search at <= 4 bits, sealed nonce
            // copied back into the builder so the gate sees real work.
            BlockFrame f{};
            std::memcpy(f.data(), b.bytes().data(), vx::blockchain::BLOCK_SIZE_BYTES);
            if (vx::blockchain::seal_pogw_nonce(f, o.difficulty_bits,
                                                uint64_t(1) << o.difficulty_bits)) {
                const auto* sr = reinterpret_cast<const vx::blockchain::RawBlock*>(f.data());
                b.set_nonce(sr->tail.pogw_nonce);
            }
        }

        const auto& raw = b.raw();
        vx::state::LedgerState ledger;
        if (vxfuzz::apply_genesis(ledger) &&
            vxfuzz::validate_then_apply(raw, o, ledger)) {
            // The state layer accepted the block: feed its transactions to
            // the mempool with real balances and nonces (TDI dust gate,
            // pending-state accounting).
            vx::state::Mempool mp;
            const uint32_t n = raw.header.tx_count;
            for (uint32_t i = 0; i < n; ++i) {
                const auto& tx = raw.transactions[i];
                const auto sender = vx::blockchain::tx_address(tx.sender_nfa);
                (void)mp.submit(tx, ledger.balance_of(sender),
                                ledger.get_next_nonce(sender));
            }
        }
    }

    // -- Layer 3: Tier-1 PQ deep chain ----------------------------------------
    if (deep_pq) {
        const PqAccount& demo = vxfuzz::demo_spender();
        uint8_t tag[16];
        bs.bytes(tag, sizeof(tag));
        const PqAccount acc = vxfuzz::make_pq_account(tag, sizeof(tag));
        Address sink{};
        bs.bytes(sink.data(), 42);

        vx::state::LedgerState ledger;
        if (!vxfuzz::apply_genesis(ledger)) return 0;
        const ChainAnchor& a = anchor();
        std::array<uint8_t, 384> coords{};

        // Height 1: the pinned one-time GENESIS_2 mint -- sender tag
        // "GENESIS_2", EXACTLY GENESIS_2_MINT_ATOMICS to the pinned demo
        // spender payload, untracked receiver, one per block. The hostile
        // second mint of ANY shape must trip the count-check that runs
        // BEFORE the shape check.
        vx::blockchain::BlockBuilder b1;
        b1.set_height(1);
        b1.set_prev_hash(a.tip_hash);
        b1.set_timestamp(now);
        b1.set_attractor_coords(coords.data());
        Transaction mint = vxfuzz::make_tx(tag_address("GENESIS_2", 9), demo.addr,
                                           vx::blockchain::GENESIS_2_MINT_ATOMICS,
                                           100, 0);
        vx::blockchain::sign_transaction(mint); // system sender: keyless digest
        (void)b1.add_transaction(mint);
        if ((bs.u8() & 1) != 0) {
            Transaction mint2 = mint;
            vx::blockchain::tx_set_amount(mint2, 1); // wrong shape on purpose
            (void)b1.add_transaction(mint2);
        }
        b1.finalize();
        vxfuzz::GateOpts o1;
        o1.expected_height = 1;
        o1.expected_prev = a.tip_hash;
        o1.prev_timestamp = a.genesis_ts;
        o1.now_unix = now;
        o1.difficulty_bits = 0;
        if (!vxfuzz::validate_then_apply(b1.raw(), o1, ledger)) return 0;

        // Height 2: witnessed spends from the demo spender (a BOUND address:
        // the ledger cross-checks the witness root against the binding).
        const uint64_t a1 =
            1 + bs.u64() % (vx::blockchain::GENESIS_2_MINT_ATOMICS - 10000);
        const uint32_t fee1 = 1 + bs.u32() % 1000;
        Transaction s1 = vxfuzz::make_tx(demo.addr, acc.addr, a1, fee1, 0);
        if (!vxfuzz::pq_sign(s1, demo.sk)) return 0;
        vx::blockchain::BlockBuilder b2;
        b2.set_height(2);
        uint8_t tip1[32];
        vx::blockchain::hash_block(b1.raw(), tip1);
        b2.set_prev_hash(tip1);
        b2.set_timestamp(now);
        b2.set_attractor_coords(coords.data());
        (void)b2.add_transaction(s1);
        const uint8_t s2sel = bs.u8() % 4;
        if (s2sel != 0) {
            // Companion spend: s2sel==2 adds a SIGNED sequential-nonce spend
            // (a real second witness, ~20 ms); the unsigned variants exercise
            // the invalid-proof, nonce-replay and overspend ladders cheaply.
            Transaction s2 = vxfuzz::make_tx(
                demo.addr, sink,
                s2sel == 1 ? a1 : 0xFFFFFFFFFFFFFFFFULL,
                1, s2sel == 2 ? 1 : (s2sel == 3 ? 1 : 0));
            if (s2sel == 2 && !vxfuzz::pq_sign(s2, demo.sk)) return 0;
            (void)b2.add_transaction(s2);
        }
        b2.finalize();
        vxfuzz::GateOpts o2;
        o2.expected_height = 2;
        o2.expected_prev = tip1;
        o2.prev_timestamp = now;
        o2.now_unix = now;
        o2.difficulty_bits = 0;
        // Mempool sees the PRE-application state: real balance + next nonce.
        vx::state::Mempool mp;
        (void)mp.submit(s1, ledger.balance_of(demo.addr),
                        ledger.get_next_nonce(demo.addr));
        if (!vxfuzz::validate_then_apply(b2.raw(), o2, ledger)) return 0;

        // Height 3: the fuzz account spends its freshly credited balance --
        // a SELF-CERTIFYING address binds on its first witnessed spend (the
        // ledger re-derives the address from the witness root). The hostile
        // variant signs with the WRONG key: the root mismatch must reject.
        Transaction s3 = vxfuzz::make_tx(acc.addr, sink, 1 + bs.u64() % a1,
                                         1 + bs.u32() % 1000, bs.u32() % 3);
        if (!vxfuzz::pq_sign(s3, acc.sk)) return 0;
        vx::blockchain::BlockBuilder b3;
        b3.set_height(3);
        uint8_t tip2[32];
        vx::blockchain::hash_block(b2.raw(), tip2);
        b3.set_prev_hash(tip2);
        b3.set_timestamp(now);
        b3.set_attractor_coords(coords.data());
        (void)b3.add_transaction(s3);
        if ((bs.u8() & 3) == 1) {
            Transaction s3h = vxfuzz::make_tx(acc.addr, sink, 42, 1, 0);
            if (!vxfuzz::pq_sign(s3h, demo.sk)) return 0; // wrong key on purpose
            (void)b3.add_transaction(s3h);
        }
        b3.finalize();
        vxfuzz::GateOpts o3;
        o3.expected_height = 3;
        o3.expected_prev = tip2;
        o3.prev_timestamp = now;
        o3.now_unix = now;
        o3.difficulty_bits = 0;
        (void)vxfuzz::validate_then_apply(b3.raw(), o3, ledger);
    }

    return 0;
}
