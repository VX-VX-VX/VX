// ChainStressTest — deterministic 1000-block hard stress chain + forensic
// analysis suite (stage E, feature freeze: test-only, no production code).
//
// Everything is driven by locally defined fixed-seed splitmix64 PRNGs, so the
// run is reproducible bit-for-bit on any machine. Phases:
//
//   BUILD   — height 1 is the pinned GENESIS_2 mint funding the demo spender;
//             heights 2..1000 each carry a MINER_ coinbase at index 0 (floor
//             claim, 50 VX) plus 0..5 PRNG transfers from the demo spender
//             and/or previously funded self-certifying PQA accounts. Every
//             block is PoGW-sealed, appended through the intake gate and
//             applied to the ledger; all frames are kept for replay.
//   ANALYZE — (a) invariant sweeps at every 100th block and at the end:
//                 total_supply + burned == issued (the exact relation the
//                 commit loop maintains — derived in sweep_invariants below),
//                 model-tracked supplies, every touched balance, every
//                 sender nonce, next_expected_height;
//             (b) 10 PRNG rollback probes: a fresh ledger replays the frame
//                 prefix, UndoEngine rolls the live ledger back to the same
//                 height, the remaining frames re-apply, and the final state
//                 must equal a cached full fresh replay exactly (all touched
//                 balances, nonces and all three supply counters);
//             (c) displaced-frames integrity: one rollback to a low height
//                 must preserve the displaced frames byte-exactly in the
//                 side journal; they re-apply as-is;
//             (d) GQC finality (separate TEST): stamps survive a store
//                 reopen, rollback below the certified height is refused
//                 (ERR_FINALIZED_BY_GQC), rollback at/above still works;
//             (e) mempool churn: 30 valid pending spends, pulled in partial
//                 batches, sealed into real blocks, remove_sealed'd — every
//                 sealed batch applies first-try and the pool drains.
//
// PoGW difficulty: 8 bits (rationale at kPogwBits below).

#include <gtest/gtest.h>

#include "vx/blockchain/block.hpp"
#include "vx/blockchain/emission.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/state/mempool.hpp"
#include "vx/state/undo_engine.hpp"
#include "vx/storage/block_store.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <ctime>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace vx::blockchain;
using vx::core::U128;
using vx::state::AddressHash;
using LedgerState = vx::state::LedgerState;
using BlockStore = vx::storage::BlockStore;
using UndoEngine = vx::state::UndoEngine;
using Mempool = vx::state::Mempool;

namespace {

// ── Fixed parameters (deterministic run-to-run) ──────────────────────────────

// PoGW difficulty for the whole stress run: the store's required_pogw_bits is
// the SINGLE source of truth on this base — the seal search (seal_pogw_nonce)
// and the intake gate both read it, so producer and verifier can never
// disagree. 8 bits costs ~2^8 = 256 expected full-frame sponge hashes
// (~0.1 ms each) per block, i.e. ~26 ms of sealing for the 1000-block build —
// the dominant cost stays far inside the 90 s GCC budget with headroom for
// the rollback replays and the ASan lane.
constexpr uint64_t kPogwBits = 8;

constexpr uint64_t kBlocks = 1000;          // heights 1..1000 above genesis
constexpr uint64_t kCheckpointEvery = 100;  // invariant sweep cadence
// Signer capacity: pq_sign_transaction refuses nonce >= 15 (leaf 15 is
// RESERVED for rollover certificates — the kernel invariant), so EVERY
// account can spend at most 15 times, ever. The pool is sized so its
// 15-leaf budget covers the ~2,500 transfers of the build with margin; the
// demo spender is capped at 8 build spends so phase 2e's funding block
// (6 spends) always fits its remaining leaves.
constexpr size_t kAccPoolSize = 240;        // pre-created PQA accounts
constexpr uint64_t kLeafBudgetPerAccount = 15;
constexpr uint64_t kDemoBuildSpendCap = 8;
constexpr size_t kSinks = 8;                // never-spending receiver tags
constexpr size_t kMiners = 8;               // MINER_ coinbase receivers

// TDI dust floor: TdiFilter::evaluate demands density
// (amountVx / 112 bytes) * 10000 >= 1.0  =>  amount >= 0.0112 VX
// = 1,120,000 atoms for a 112-byte transaction. Every generated amount
// respects it (mempool admission re-checks the same filter).
constexpr uint64_t kTdiDustAtoms112B = 1'120'000ULL;

constexpr uint64_t kMaxAmountAtoms = 30'000'000ULL;  // 0.3 VX per transfer cap
constexpr uint64_t kMinFee = 100, kMaxFee = 5'000;   // per-transfer fee range
constexpr uint64_t kMinerFloorAtoms =
    vx::blockchain::BLOCK_REWARD_BASE_VX * vx::blockchain::ATOMS_PER_VX; // 5e9
constexpr uint64_t kMaxBlockFees = 5ULL * kMaxFee;   // <= 5 user txs per block

// Fixed PRNG seeds (splitmix64) — one per phase so reshuffling a phase never
// perturbs the others.
constexpr uint64_t kSeedBuild = 0x243F6A8885A308D3ull;     // build: txs/amounts
constexpr uint64_t kSeedProbes = 0x13198A2E03707344ull;    // rollback probes
constexpr uint64_t kSeedDisplaced = 0xA4093822299F31D0ull; // phase (c) height
constexpr uint64_t kSeedChurn = 0x082EFA98EC4E6C89ull;     // mempool churn
constexpr uint64_t kSeedGqc = 0x452821E638D01377ull;       // GQC mini-chain

constexpr uint64_t kProbeCount = 10;

// The header timestamp every block of the chain under construction carries.
// A CONSTANT timestamp (never decreasing, never more than 300 s in the future
// even for a slow machine — the intake gate rejects a header timestamp above
// now + 300) keeps the build gate-proof for any build duration.
uint64_t g_chain_ts = 0;

// Splitmix64: tiny, self-contained, fixed-seed — every "random" choice in
// this file comes from one of the seeds above and reproduces exactly.
struct SplitMix64 {
    uint64_t s;
    explicit SplitMix64(uint64_t seed) : s(seed) {}
    uint64_t next() {
        s += 0x9E3779B97F4A7C15ull;
        uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    uint64_t below(uint64_t n) { return n == 0 ? 0 : next() % n; }
};

std::string temp_dir(const char* tag) {
    auto dir = std::filesystem::temp_directory_path() /
               (std::string(tag) + "_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    return dir.string();
}

// 42-byte NFA payload address from an ASCII tag (zero-padded tail).
Address addr_of(const std::string& s) {
    Address a{};
    std::memcpy(a.data(), s.data(), s.size() < 42 ? s.size() : 42);
    return a;
}

Address stress_miner_addr(size_t i) {
    char tag[48];
    std::snprintf(tag, sizeof(tag), "VX_STRESS_MINER_%zu_TAG_000000000", i);
    return addr_of(tag);
}

Address stress_sink_addr(size_t i) {
    char tag[48];
    std::snprintf(tag, sizeof(tag), "VX_STRESS_SINK_%zu_TAG_0000000000", i);
    return addr_of(tag);
}

std::string addr_key(const Address& a) {
    return std::string(reinterpret_cast<const char*>(a.data()), a.size());
}

// A test account bound to a post-quantum WOTS+/XMSS key: the address is
// SELF-CERTIFYING ("PQA" + base64url of Sponge("VXPQADDRV1" || root)), so
// holding the key IS holding the address (BACKLOG 0.7) — funding such an
// account by a plain transfer is enough; its first witnessed spend binds it.
struct PqAccount {
    std::array<uint8_t, 32> sk{};
    std::array<uint8_t, 32> root{};
    Address addr{};
};

PqAccount make_pq_account(const char* tag) {
    PqAccount acc;
    VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag),
                             std::strlen(tag), acc.sk.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(acc.sk);
    acc.root = vx::crypto::pq::xmss_root(acc.sk, pub_seed);
    derive_pq_address(acc.root.data(), acc.addr.data());
    return acc;
}

PqAccount make_demo_spender() {
    PqAccount demo = make_pq_account("VX_DEMO_SPENDER_SK_V1");
    // The demo spender is a BOUND (not self-certifying) address: the binding
    // table maps the attractor-derived Address #2 payload to the root of the
    // public demo key, so this account couples that key with the pinned
    // GENESIS_2 receiver payload.
    demo.addr = genesis2_mint_receiver_payload();
    return demo;
}

bool pq_sign(Transaction& tx, const PqAccount& acc) {
    return vx::crypto::pq::pq_sign_transaction(tx, acc.sk);
}

Transaction make_tx(const Address& sender, const Address& receiver,
                    uint64_t amount, uint32_t nonce) {
    Transaction tx{};
    std::memcpy(tx.sender_nfa, sender.data(), 42);
    std::memcpy(tx.receiver_nfa, receiver.data(), 42);
    tx_set_amount(tx, amount);
    tx_set_fee(tx, 100);
    tx_set_nonce(tx, nonce);
    return tx;
}

Transaction make_tx_fee(const Address& sender, const Address& receiver,
                        uint64_t amount, uint32_t fee, uint32_t nonce) {
    Transaction tx = make_tx(sender, receiver, amount, nonce);
    tx_set_fee(tx, fee);
    return tx;
}

// MINER_ coinbase claiming the guaranteed 50 VX floor: the ledger recomputes
// the entitlement from the frame hash (floor 5e9 atoms for any hash, bonus
// tiers above), so the floor claim is valid for every block this suite seals.
Transaction make_coinbase(const Address& receiver, uint64_t height,
                          const uint8_t prev_tip[32]) {
    Transaction cb{};
    std::memcpy(cb.sender_nfa, "MINER_", 6);
    for (size_t i = 6; i < 42; ++i) cb.sender_nfa[i] = '0';
    std::memcpy(cb.receiver_nfa, receiver.data(), 42);
    tx_set_amount(cb, kMinerFloorAtoms);
    tx_set_fee(cb, 0);
    tx_set_nonce(cb, 0);
    set_coinbase_binding(cb, height, prev_tip);
    return cb;
}

BlockBuilder next_block(BlockStore& store, uint64_t ts) {
    BlockBuilder b;
    b.set_height(store.chain_height());
    b.set_timestamp(ts);
    uint8_t tip[32];
    store.tip_hash(tip);
    b.set_prev_hash(tip);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    return b;
}

bool seal_and_append(BlockStore& store, BlockBuilder& b, BlockFrame& out) {
    b.finalize();
    std::memcpy(out.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    if (!seal_pogw_nonce(out, store.required_pogw_bits())) return false;
    return store.append_block(out);
}

// ── Deterministic economy model ──────────────────────────────────────────────
// The model mirrors the ledger commit loop exactly: a transfer moves
// (amount + fee) out of the sender and credits `amount` to the receiver, the
// fee reaches nobody except through the coinbase entitlement, the TDI burn
// floors fees at 50%, and the coinbase credits kMinerFloorAtoms. Every
// address this suite ever touches is registered in the model, so the sweeps
// compare ALL state this suite could have mutated, not a sample.

struct ChainModel {
    std::unordered_map<Address, U128, AddressHash> balance;
    std::unordered_map<Address, uint64_t, AddressHash> spent_count;
    U128 total{0}, issued{0}, burned{0};

    U128 bal(const Address& a) const {
        const auto it = balance.find(a);
        return it == balance.end() ? U128{} : it->second;
    }
    uint64_t spent(const Address& a) const {
        const auto it = spent_count.find(a);
        return it == spent_count.end() ? 0 : it->second;
    }
    void credit(const Address& a, const U128& v) { balance[a] = balance[a] + v; }
    void debit(const Address& a, const U128& v) {
        // The model must never drive a balance negative; a violation is a
        // suite bug (the generated economy overdraws), not a ledger one.
        const U128 cur = bal(a);
        ASSERT_LE(v, cur) << "model overdraw (suite bug)";
        balance[a] = cur - v;
    }
};

// Everything one chain build produces and every later phase replays.
struct ChainRecord {
    std::vector<BlockFrame> frames;   // heights 1..N (genesis #0 kept apart)
    BlockFrame genesis_frame{};
    std::vector<Address> touched;     // unique addresses ever seen
    std::unordered_set<std::string> touched_keys;
    ChainModel model;
    uint64_t n_blocks = 0;

    void touch(const Address& a) {
        if (touched_keys.insert(addr_key(a)).second) touched.push_back(a);
    }
};

// Open a fresh store (auto-seeded from the deterministic genesis.bin) and a
// ledger that has applied height 0.
struct ChainCtx {
    std::unique_ptr<BlockStore> store;
    std::unique_ptr<LedgerState> ledger;
};

ChainCtx open_chain(const std::string& dir, const char* store_name) {
    ChainCtx ctx;
    ctx.store = std::make_unique<BlockStore>(dir + "/" + store_name,
                                             "genesis.bin", kPogwBits);
    ctx.ledger = std::make_unique<LedgerState>();
    const auto* g = ctx.store->get_block(0);
    EXPECT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
    const auto res = ctx.ledger->apply_block(BlockView(gf));
    EXPECT_TRUE(res.ok) << res.error;
    return ctx;
}

// The supply invariant that ACTUALLY holds on this base, derived from
// LedgerState::apply_block's commit loop (src/state/ledger_state.hpp):
//
//   * every non-coinbase tx debits its sender (amount + fee) and credits
//     its receiver (amount):  D(sum of balances) = -total_fees per block;
//   * the commit loop then does  burned_supply_ += burned  and
//     issued_supply_ += block_issuance,  where the emission gate computes
//     burned = total_fees / 2  and
//     block_issuance = (genesis_mint_sum + miner_mint_sum) - recredited,
//     recredited = min(miner_mint_sum, miner_reward),
//     miner_reward = total_fees - burned;
//   * this suite always claims the 50 VX floor (5e9 atoms) and keeps per-
//     block fees <= 5 x 5,000 atoms = 25,000 << 2.5e9, so miner_reward <
//     miner_mint_sum and recredited == miner_reward, hence per block:
//         D(total)  = coinbase - fees
//         D(issued) - D(burned) = (coinbase - miner_reward) - burned
//                               = coinbase - (fees - burned) - burned
//                               = coinbase - fees.   Equal.
//
// Therefore the exact running relation is:
//     total_supply() + total_burned() == issued_supply()
// with the height-1 GENESIS_2 mint and every MINER_ coinbase booked into
// `issued` and every TDI fee burn into `burned`. The sweep asserts that
// relation directly, plus the fully model-tracked quantities (all three
// supply counters, every touched balance, every sender nonce, the tracked
// account count and the height pointer).
void sweep_invariants(const LedgerState& ledger, const ChainRecord& rec,
                      uint64_t expected_next_height, const char* where) {
    SCOPED_TRACE(std::string("sweep at ") + where);
    EXPECT_EQ(ledger.next_expected_height(), expected_next_height)
        << where << ": height pointer drifted";
    EXPECT_EQ(ledger.total_supply() + ledger.total_burned(),
              ledger.issued_supply())
        << where << ": total + burned != issued (supply relation broken)";
    EXPECT_EQ(ledger.total_supply(), rec.model.total)
        << where << ": total supply left the model";
    EXPECT_EQ(ledger.issued_supply(), rec.model.issued)
        << where << ": issued supply left the model";
    EXPECT_EQ(ledger.total_burned(), rec.model.burned)
        << where << ": burned supply left the model";
    EXPECT_EQ(ledger.accounts().size(), rec.model.balance.size())
        << where << ": tracked account set left the model";
    for (const auto& a : rec.touched) {
        EXPECT_EQ(ledger.balance_of(a), rec.model.bal(a))
            << where << ": balance drift on a touched address";
    }
    for (const auto& [addr, cnt] : rec.model.spent_count) {
        EXPECT_EQ(ledger.get_next_nonce(addr), static_cast<uint32_t>(cnt))
            << where << ": nonce drift on a funded sender";
    }
}

// Per-checkpoint supply snapshot (the rollback probes pin their fresh prefix
// replays against values already verified against the live ledger).
struct SupplySnap {
    U128 total, issued, burned;
};

// Books the fee consequences of one block into the model (TDI burn + the
// fee-share issue reduction). Call once per block, after all transfers.
void book_fees(ChainModel& model, const U128& fees_sum) {
    const U128 burn = fees_sum / U128(2);
    model.burned = model.burned + burn;
    model.total = model.total - fees_sum;
    model.issued = model.issued - (fees_sum - burn);
}

// Builds the deterministic economy chain into ctx (which must already have
// height 0 applied). Journals every block through `undo` in the resync
// ordering (journal BEFORE the store append, as the reorg path does), so
// every later rollback finds full journal coverage.
void build_blocks(ChainCtx& ctx, UndoEngine& undo, ChainRecord& rec,
                  uint64_t n_blocks, uint64_t seed,
                  std::vector<SupplySnap>* snaps) {
    LedgerState& ledger = *ctx.ledger;
    BlockStore& store = *ctx.store;
    g_chain_ts = static_cast<uint64_t>(std::time(nullptr));
    rec.n_blocks = n_blocks;

    // Baseline: seed the model with the verified post-genesis state.
    {
        const auto* g = store.get_block(0);
        ASSERT_NE(g, nullptr);
        std::memcpy(rec.genesis_frame.data(),
                    reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
        const BlockView gv(rec.genesis_frame);
        for (uint32_t i = 0; i < gv.header().tx_count; ++i) {
            rec.touch(tx_address(gv.tx(i).sender_nfa));
            rec.touch(tx_address(gv.tx(i).receiver_nfa));
        }
        for (const auto& [addr, bal] : ledger.accounts()) {
            rec.model.balance[addr] = bal;
            rec.touch(addr);
        }
        rec.model.total = ledger.total_supply();
        rec.model.issued = ledger.issued_supply();
        rec.model.burned = ledger.total_burned();
    }

    const PqAccount demo = make_demo_spender();

    // The PQA account pool (self-certifying addresses) + static sinks and
    // miner receivers. All deterministic tags.
    std::vector<PqAccount> pool;
    pool.reserve(kAccPoolSize);
    for (size_t i = 0; i < kAccPoolSize; ++i) {
        char tag[48];
        std::snprintf(tag, sizeof(tag), "VX_STRESS_ACC_%03zu_V1", i);
        pool.push_back(make_pq_account(tag));
    }
    for (size_t i = 0; i < kSinks; ++i) rec.touch(stress_sink_addr(i));
    for (size_t i = 0; i < kMiners; ++i) rec.touch(stress_miner_addr(i));
    for (const auto& a : pool) rec.touch(a.addr);
    rec.touch(demo.addr);

    SplitMix64 rng(seed);

    for (uint64_t h = 1; h <= n_blocks; ++h) {
        uint8_t tip[32];
        store.tip_hash(tip);
        BlockBuilder b = next_block(store, g_chain_ts);

        U128 fees_sum{0};

        if (h == 1) {
            // The ONLY keyless mint: the pinned GENESIS_2 shape — exact
            // amount, exact receiver (the demo spender payload), untracked
            // receiver, one mint in the block (the ledger's count-check
            // precedes its shape-check).
            Transaction mint = make_tx(addr_of("GENESIS_2"), demo.addr,
                                       GENESIS_2_MINT_ATOMICS, 0);
            sign_transaction(mint); // system sender: structural digest only
            ASSERT_TRUE(b.add_transaction(mint));
            rec.model.credit(demo.addr, U128(GENESIS_2_MINT_ATOMICS));
            rec.model.total = rec.model.total + U128(GENESIS_2_MINT_ATOMICS);
            rec.model.issued = rec.model.issued + U128(GENESIS_2_MINT_ATOMICS);
        } else {
            // Coinbase: index 0, floor claim, chain-position bound.
            const Address miner_recv = stress_miner_addr(rng.below(kMiners));
            ASSERT_TRUE(b.add_transaction(make_coinbase(miner_recv, h, tip)));
            rec.model.credit(miner_recv, U128(kMinerFloorAtoms));
            rec.model.total = rec.model.total + U128(kMinerFloorAtoms);
            rec.model.issued = rec.model.issued + U128(kMinerFloorAtoms);

            // 0..5 transfers from the demo spender and/or previously funded
            // PQA accounts. Senders need dust + fee headroom; receivers are
            // existing funded accounts, brand-new (first funding of a pool
            // account) or never-spending sinks.
            const uint32_t n_tx = static_cast<uint32_t>(rng.below(6));
            const uint64_t kEligible = kTdiDustAtoms112B + kMaxFee;
            for (uint32_t t = 0; t < n_tx; ++t) {
                // Leaf-budget-aware eligibility: an account whose 15 tx
                // leaves are spent can never sign again (leaf 15 is the
                // reserved cert leaf; the signer refuses nonce >= 15), so
                // it leaves the sender rotation.
                // The demo spender keeps 8 of its leaves for phase 2e.
                bool demo_eligible =
                    rec.model.bal(demo.addr) >= U128(kEligible) &&
                    rec.model.spent(demo.addr) < kDemoBuildSpendCap;
                std::vector<size_t> elig;
                for (size_t i = 0; i < pool.size(); ++i) {
                    if (rec.model.bal(pool[i].addr) >= U128(kEligible) &&
                        rec.model.spent(pool[i].addr) < kLeafBudgetPerAccount)
                        elig.push_back(i);
                }
                Address sender, receiver;
                const PqAccount* signer = nullptr;
                if (demo_eligible && (elig.empty() || rng.below(2) == 0)) {
                    sender = demo.addr;
                    signer = &demo;
                } else if (!elig.empty()) {
                    const size_t idx = elig[rng.below(elig.size())];
                    sender = pool[idx].addr;
                    signer = &pool[idx];
                } else {
                    break; // nobody eligible yet (early blocks only)
                }

                // Receiver: 50% another funded pool account, 25% a fresh
                // (still unfunded) pool account, 25% a sink; never the
                // sender itself (senders are demo/PQA, sinks are tagged).
                const uint64_t roll = rng.below(100);
                bool picked = false;
                if (roll < 50) {
                    std::vector<size_t> funded;
                    for (size_t i = 0; i < pool.size(); ++i) {
                        if (pool[i].addr != sender &&
                            rec.model.bal(pool[i].addr) > U128{})
                            funded.push_back(i);
                    }
                    if (!funded.empty()) {
                        receiver = pool[funded[rng.below(funded.size())]].addr;
                        picked = true;
                    }
                }
                if (!picked && roll < 75) {
                    for (size_t tries = 0; tries < pool.size(); ++tries) {
                        const size_t j = rng.below(pool.size());
                        if (pool[j].addr != sender &&
                            rec.model.bal(pool[j].addr) == U128{}) {
                            receiver = pool[j].addr;
                            picked = true;
                            break;
                        }
                    }
                }
                if (!picked) receiver = stress_sink_addr(rng.below(kSinks));

                // Amount respects the TDI dust floor and the sender's real
                // headroom; fee is a random market fee.
                const uint64_t bal = rec.model.bal(sender).lo;
                const uint32_t fee = static_cast<uint32_t>(
                    kMinFee + rng.below(kMaxFee - kMinFee + 1));
                ASSERT_LE(U128(fee), rec.model.bal(sender))
                    << "suite bug: fee exceeds the modeled balance";
                const uint64_t room = bal - fee;
                const uint64_t cap = std::min<uint64_t>(room, kMaxAmountAtoms);
                ASSERT_GE(cap, kTdiDustAtoms112B)
                    << "suite bug: dust infeasible";
                const uint64_t amount =
                    kTdiDustAtoms112B + rng.below(cap - kTdiDustAtoms112B + 1);

                Transaction tx = make_tx_fee(
                    sender, receiver, amount, fee,
                    static_cast<uint32_t>(rec.model.spent(sender)));
                ASSERT_TRUE(pq_sign(tx, *signer));
                ASSERT_TRUE(b.add_transaction(tx));
                rec.model.debit(sender, U128(amount) + U128(fee));
                rec.model.credit(receiver, U128(amount));
                fees_sum = fees_sum + U128(fee);
                rec.model.spent_count[sender] += 1;
                rec.touch(sender);
                rec.touch(receiver);
            }
            book_fees(rec.model, fees_sum);
        }

        // Seal + journal + append + apply (the ledger is the authority).
        BlockFrame frame;
        ASSERT_TRUE(seal_and_append(store, b, frame))
            << "seal/append failed at height " << h << ": "
            << store.last_error();
        undo.apply_block(BlockView(frame));
        const auto res = ledger.apply_block(BlockView(frame));
        ASSERT_TRUE(res.ok) << "apply refused at height " << h << ": "
                            << res.error;
        rec.frames.push_back(frame);

        if (h % kCheckpointEvery == 0) {
            sweep_invariants(ledger, rec, h + 1, "build checkpoint");
            if (snaps) {
                snaps->push_back({ledger.total_supply(),
                                  ledger.issued_supply(),
                                  ledger.total_burned()});
            }
        }
    }
    sweep_invariants(ledger, rec, n_blocks + 1, "build end");
}

// A full fresh replay of genesis + frames 1..N into a brand-new ledger (the
// rollback probes compare the rolled-back-and-reapplied live ledger against
// this state exactly).
struct ReplayExpectation {
    U128 total, issued, burned;
    std::unordered_map<Address, U128, AddressHash> balance;
    std::unordered_map<Address, uint32_t, AddressHash> nonce;
    uint64_t next_height = 0;
};

ReplayExpectation fresh_replay(const ChainRecord& rec) {
    LedgerState fresh;
    const auto g = fresh.apply_block(BlockView(rec.genesis_frame));
    EXPECT_TRUE(g.ok) << g.error;
    for (const auto& f : rec.frames) {
        const auto res = fresh.apply_block(BlockView(f));
        EXPECT_TRUE(res.ok) << "fresh replay refused: " << res.error;
    }
    ReplayExpectation e;
    e.total = fresh.total_supply();
    e.issued = fresh.issued_supply();
    e.burned = fresh.total_burned();
    e.next_height = fresh.next_expected_height();
    for (const auto& a : rec.touched) {
        // Only TRACKED addresses form the account map (an address the
        // economy never funded stays untracked with a zero balance); the
        // size comparison in expect_matches_replay depends on that.
        if (fresh.tracked_addresses_containing(a)) {
            e.balance[a] = fresh.balance_of(a);
        }
        e.nonce[a] = fresh.get_next_nonce(a);
    }
    return e;
}

void expect_matches_replay(const LedgerState& ledger,
                           const ReplayExpectation& e,
                           const ChainRecord& rec, const char* where) {
    EXPECT_EQ(ledger.total_supply(), e.total) << where;
    EXPECT_EQ(ledger.issued_supply(), e.issued) << where;
    EXPECT_EQ(ledger.total_burned(), e.burned) << where;
    EXPECT_EQ(ledger.next_expected_height(), e.next_height) << where;
    EXPECT_EQ(ledger.accounts().size(), e.balance.size()) << where;
    for (const auto& a : rec.touched) {
        // The tracked account SETS must coincide (the rollback forget loop
        // untracks exactly the addresses the rolled-back fork created).
        const bool tracked_in_replay = e.balance.count(a) != 0;
        const bool tracked_live = ledger.tracked_addresses_containing(a);
        EXPECT_EQ(tracked_in_replay, tracked_live)
            << where << ": tracked-set mismatch on a touched address";
        if (tracked_in_replay && tracked_live) {
            EXPECT_EQ(ledger.balance_of(a), e.balance.at(a))
                << where
                << ": touched balance mismatch after rollback+re-apply";
        }
        EXPECT_EQ(ledger.get_next_nonce(a), e.nonce.at(a))
            << where << ": touched nonce mismatch after rollback+re-apply";
    }
}

// Builds one sealed block carrying a MINER_ coinbase + the given user txs,
// journals it, appends it and applies it; books the model. Returns false via
// ASSERT on any failure (the block MUST apply first-try in every phase that
// uses this).
void seal_append_apply(ChainCtx& ctx, UndoEngine& undo, ChainRecord& rec,
                       const Address& miner_recv, uint64_t ts,
                       const std::vector<Transaction>& user_txs) {
    const uint64_t h = ctx.store->chain_height();
    uint8_t tip[32];
    ctx.store->tip_hash(tip);
    BlockBuilder b = next_block(*ctx.store, ts);
    ASSERT_TRUE(b.add_transaction(make_coinbase(miner_recv, h, tip)));
    rec.model.credit(miner_recv, U128(kMinerFloorAtoms));
    rec.model.total = rec.model.total + U128(kMinerFloorAtoms);
    rec.model.issued = rec.model.issued + U128(kMinerFloorAtoms);

    U128 fees_sum{0};
    for (const auto& tx : user_txs) {
        ASSERT_TRUE(b.add_transaction(tx));
        const Address sender = tx_address(tx.sender_nfa);
        const Address receiver = tx_address(tx.receiver_nfa);
        const uint64_t amount = tx_amount(tx);
        const uint32_t fee = tx_fee(tx);
        rec.model.debit(sender, U128(amount) + U128(fee));
        rec.model.credit(receiver, U128(amount));
        fees_sum = fees_sum + U128(fee);
        rec.model.spent_count[sender] += 1;
        rec.touch(sender);
        rec.touch(receiver);
    }
    book_fees(rec.model, fees_sum);

    BlockFrame frame;
    ASSERT_TRUE(seal_and_append(*ctx.store, b, frame))
        << "seal/append failed at height " << h << ": "
        << ctx.store->last_error();
    undo.apply_block(BlockView(frame));
    const auto res = ctx.ledger->apply_block(BlockView(frame));
    ASSERT_TRUE(res.ok) << "block at height " << h << " did NOT apply"
                        << " first-try: " << res.error;
    rec.frames.push_back(frame);
}

// Submits a signed transaction to the mempool with the live ledger's view of
// the sender (balance + next nonce).
vx::state::SubmitResult pool_submit_ok(Mempool& mem, const Transaction& tx,
                                       const ChainCtx& ctx) {
    const Address sender = tx_address(tx.sender_nfa);
    return mem.submit(tx, ctx.ledger->balance_of(sender),
                      ctx.ledger->get_next_nonce(sender));
}

} // namespace

// ── Phases 1, 2a, 2b, 2c, 2e: the 1000-block chain and its analysis ─────────

TEST(ChainStressTest, BuildAnalyzeRollbackAndMempoolChurn) {
    const std::string dir = temp_dir("vx_stress_main");
    ChainCtx ctx = open_chain(dir, "stress.vxb");
    UndoEngine undo(dir, *ctx.store, *ctx.ledger);
    ChainRecord rec;

    // ── Phase 1: BUILD (1000 blocks; sweeps run every 100 blocks inside) ───
    std::vector<SupplySnap> snaps;
    build_blocks(ctx, undo, rec, kBlocks, kSeedBuild, &snaps);
    ASSERT_EQ(rec.frames.size(), kBlocks);
    ASSERT_EQ(snaps.size(), kBlocks / kCheckpointEvery);
    std::cout << "  [build] " << kBlocks << " blocks, " << rec.touched.size()
              << " touched addresses, total supply "
              << ctx.ledger->total_supply().lo << " atoms\n";

    // ── Phase 2c first (the displaced journal is append-only, so the byte-
    // exact integrity check must run before any other rollback pollutes the
    // side file): one PRNG-chosen low rollback; the displaced frames must
    // come back byte-exact and re-apply as-is.
    {
        SplitMix64 rng(kSeedDisplaced);
        const uint64_t low = 40 + rng.below(60); // a low height in [40, 99]
        SCOPED_TRACE("displaced-frames rollback");
        ASSERT_TRUE(undo.rollback_to_height(low)) << undo.last_error();
        EXPECT_EQ(ctx.ledger->next_expected_height(), low + 1);

        const auto displaced = undo.load_displaced_frames();
        ASSERT_EQ(displaced.size(), kBlocks - low)
            << "the side journal must hold every displaced frame";
        for (size_t i = 0; i < displaced.size(); ++i) {
            EXPECT_EQ(displaced[i].height, low + 1 + i);
            ASSERT_EQ(0, std::memcmp(displaced[i].frame.data(),
                                     rec.frames[low + i].data(),
                                     BLOCK_SIZE_BYTES))
                << "displaced frame at height " << low + 1 + i
                << " is not byte-exact";
        }
        // Re-apply from the DISPLACED copies themselves (not from the kept
        // vector) — the strongest form of "the rollback is replayable".
        for (const auto& d : displaced) {
            undo.apply_block(BlockView(d.frame));
            const auto res = ctx.ledger->apply_block(BlockView(d.frame));
            ASSERT_TRUE(res.ok) << "displaced re-apply refused: " << res.error;
        }
        sweep_invariants(*ctx.ledger, rec, kBlocks + 1,
                         "after displaced re-apply");
        std::cout << "  [displaced] " << displaced.size()
                  << " frames preserved byte-exact through the rollback to "
                  << low << " and re-applied\n";
    }

    // ── Phase 2b: rollback probes ───────────────────────────────────────────
    {
        SplitMix64 rng(kSeedProbes);
        std::vector<uint64_t> probes;
        while (probes.size() < kProbeCount) {
            const uint64_t h = 50 + rng.below(900); // in [50, 949]
            if (std::find(probes.begin(), probes.end(), h) == probes.end())
                probes.push_back(h);
        }
        // One cached full fresh replay: the chain is identical for every
        // probe, so each re-applied live ledger must match THIS state.
        const ReplayExpectation full = fresh_replay(rec);
        ASSERT_EQ(full.next_height, kBlocks + 1);

        for (const uint64_t h : probes) {
            SCOPED_TRACE(std::string("rollback probe to height ") +
                         std::to_string(h));
            // Fresh prefix replay -> the expectations the live ledger must
            // land on after the rollback (supplies + every touched balance
            // and nonce).
            LedgerState fresh_prefix;
            ASSERT_TRUE(
                fresh_prefix.apply_block(BlockView(rec.genesis_frame)).ok);
            for (uint64_t i = 0; i < h; ++i) {
                const auto res =
                    fresh_prefix.apply_block(BlockView(rec.frames[i]));
                ASSERT_TRUE(res.ok) << "prefix replay refused: " << res.error;
            }
            // When the probe lands exactly on a swept checkpoint height,
            // the fresh prefix must also agree with that checkpoint's
            // supply snapshot (already verified against the live ledger
            // during the build).
            if (h % kCheckpointEvery == 0) {
                const SupplySnap& snap = snaps[h / kCheckpointEvery - 1];
                EXPECT_EQ(fresh_prefix.total_supply(), snap.total);
                EXPECT_EQ(fresh_prefix.issued_supply(), snap.issued);
                EXPECT_EQ(fresh_prefix.total_burned(), snap.burned);
            }

            ASSERT_TRUE(undo.rollback_to_height(h)) << undo.last_error();
            EXPECT_EQ(ctx.ledger->next_expected_height(), h + 1);
            EXPECT_EQ(ctx.ledger->total_supply(), fresh_prefix.total_supply());
            EXPECT_EQ(ctx.ledger->issued_supply(),
                      fresh_prefix.issued_supply());
            EXPECT_EQ(ctx.ledger->total_burned(),
                      fresh_prefix.total_burned());
            for (const auto& a : rec.touched) {
                EXPECT_EQ(ctx.ledger->balance_of(a),
                          fresh_prefix.balance_of(a))
                    << "post-rollback balance mismatch at height " << h;
                EXPECT_EQ(ctx.ledger->get_next_nonce(a),
                          fresh_prefix.get_next_nonce(a))
                    << "post-rollback nonce mismatch at height " << h;
            }

            // Re-apply the remaining frames; the final state must equal the
            // cached full fresh replay EXACTLY.
            for (uint64_t i = h; i < kBlocks; ++i) {
                undo.apply_block(BlockView(rec.frames[i]));
                const auto res =
                    ctx.ledger->apply_block(BlockView(rec.frames[i]));
                ASSERT_TRUE(res.ok) << "re-apply refused after rollback to "
                                    << h << ": " << res.error;
            }
            expect_matches_replay(*ctx.ledger, full, rec, "probe re-applied");
            sweep_invariants(*ctx.ledger, rec, kBlocks + 1, "probe re-applied");
        }
        std::cout << "  [rollback] " << probes.size()
                  << " probes: rollback + re-apply always converges to the"
                  << " fresh replay state\n";
    }

    // ── Phase 2e: mempool churn on the live chain segment ───────────────────
    {
        SplitMix64 rng(kSeedChurn);
        Mempool mem;

        // Six churn senders — FRESH accounts (their own XMSS leaf budget,
        // untouched by the build), funded by one sealed funding block so the
        // 30 pending spends always fit their pending-balance guard.
        std::vector<PqAccount> churn;
        for (size_t i = 0; i < 6; ++i) {
            char tag[48];
            std::snprintf(tag, sizeof(tag), "VX_STRESS_CHURN_%02zu_V1", i);
            churn.push_back(make_pq_account(tag));
            rec.touch(churn.back().addr);
        }
        const PqAccount demo = make_demo_spender();

        {
            // The demo spender reserved 8 build spends; the 6 funding txs
            // must fit the remaining XMSS leaves (nonce >= 16 cannot sign).
            ASSERT_LE(rec.model.spent(demo.addr) + churn.size(),
                      kLeafBudgetPerAccount)
                << "suite bug: demo spender would exceed its leaf budget";
            std::vector<Transaction> fund;
            uint32_t nonce = ctx.ledger->get_next_nonce(demo.addr);
            for (const auto& acc : churn) {
                fund.push_back(make_tx_fee(demo.addr, acc.addr, 300'000'000ULL,
                                           500, nonce++));
                ASSERT_TRUE(pq_sign(fund.back(), demo));
            }
            seal_append_apply(ctx, undo, rec, stress_miner_addr(0),
                              g_chain_ts + 1, fund);
        }

        // 30 valid pending spends across the six churn senders. The nonce
        // chain is tracked LOCALLY: mempool submits advance the sender's
        // pending nonce without touching the ledger's committed counter.
        constexpr size_t kChurnTxs = 30;
        std::unordered_map<Address, uint32_t, AddressHash> churn_nonce;
        for (const auto& acc : churn) {
            churn_nonce[acc.addr] = ctx.ledger->get_next_nonce(acc.addr);
        }
        for (size_t s = 0; s < kChurnTxs; ++s) {
            const PqAccount& acc = churn[s % churn.size()];
            const uint64_t amount = 12'000'000ULL + rng.below(15'000'000ULL);
            const uint32_t fee =
                static_cast<uint32_t>(100 + rng.below(900));
            const uint32_t nonce = churn_nonce[acc.addr]++;
            Transaction tx = make_tx_fee(acc.addr, stress_sink_addr(0),
                                         amount, fee, nonce);
            ASSERT_TRUE(pq_sign(tx, acc));
            const auto sub = pool_submit_ok(mem, tx, ctx);
            ASSERT_TRUE(sub.ok) << "churn submit refused: " << sub.error;
        }
        EXPECT_EQ(mem.count(), kChurnTxs);
        const auto st0 = mem.stats();
        EXPECT_EQ(st0.count, kChurnTxs);
        EXPECT_EQ(st0.byte_occupancy, kChurnTxs * 112);

        // Pull in partial batches of 7; seal each batch as a real block;
        // every sealed batch must apply FIRST-TRY; remove_sealed drains.
        size_t sealed_total = 0;
        std::unordered_set<std::string> sealed_ids;
        while (!mem.empty()) {
            const auto batch = mem.pull_for_sealing(7);
            ASSERT_FALSE(batch.empty());
            ASSERT_LE(batch.size(), size_t(7));
            seal_append_apply(ctx, undo, rec,
                              stress_miner_addr(sealed_total % kMiners),
                              g_chain_ts + 1, batch);
            mem.remove_sealed(batch);
            for (const auto& tx : batch) {
                sealed_ids.insert(addr_key(tx_address(tx.sender_nfa)) + ":" +
                                  std::to_string(tx_nonce(tx)));
            }
            sealed_total += batch.size();
        }
        EXPECT_TRUE(mem.empty());
        EXPECT_EQ(mem.count(), size_t(0));
        EXPECT_EQ(sealed_total, kChurnTxs);
        EXPECT_EQ(sealed_ids.size(), kChurnTxs)
            << "every pending spend must be sealed exactly once";
        std::cout << "  [mempool] " << kChurnTxs << " pending spends sealed ("
                  << sealed_total << " txs, "
                  << (kChurnTxs + 6) / 7 << " batches); pool drained, every"
                  << " batch applied first-try\n";

        sweep_invariants(*ctx.ledger, rec, ctx.store->chain_height(),
                         "after mempool churn");
    }

    std::filesystem::remove_all(dir);
}

// ── Phase 2d: GQC finality checkpoints ──────────────────────────────────────

TEST(ChainStressTest, GqcCheckpointsSurviveReopenAndRefuseRollback) {
    const std::string dir = temp_dir("vx_stress_gqc");
    const std::string store_path = dir + "/gqc.vxb";
    ChainRecord rec;
    {
        ChainCtx ctx = open_chain(dir, "gqc.vxb");
        UndoEngine undo(dir, *ctx.store, *ctx.ledger);
        build_blocks(ctx, undo, rec, 24, kSeedGqc, nullptr);
        ASSERT_EQ(rec.frames.size(), 24ull)
            << "the GQC mini-chain build did not complete";

        // Certify three heights: the aggregate is any deterministic 32-byte
        // commitment; the versioned sidecar record is what the guard
        // replays on reopen.
        for (const uint64_t h : {uint64_t{5}, uint64_t{12}, uint64_t{20}}) {
            const std::string tag = "VX_STRESS_GQC_AGG_V1_" + std::to_string(h);
            uint8_t agg[32];
            VortexSponge256::compute(
                reinterpret_cast<const uint8_t*>(tag.data()), tag.size(), agg);
            ASSERT_TRUE(ctx.store->stamp_gqc(h, agg))
                << "GQC stamp refused at height " << h;
            uint8_t back[32];
            ASSERT_TRUE(ctx.store->gqc_stamp(h, back));
            EXPECT_EQ(0, std::memcmp(agg, back, 32));
        }
        // The destructor commits the journal so the reopened UndoEngine
        // finds full coverage.
    }

    // Reopen the store: the checkpoint must survive (highest_gqc_stamp).
    {
        BlockStore store2(store_path, "genesis.bin", kPogwBits);
        bool clean = false;
        EXPECT_EQ(store2.highest_gqc_stamp(clean), 20ull);
        EXPECT_TRUE(clean) << "the GQC sidecar must parse cleanly on reopen";

        // A live ledger replayed to the same tip + the reloaded journal.
        LedgerState ledger2;
        ASSERT_TRUE(ledger2.apply_block(BlockView(rec.genesis_frame)).ok);
        for (const auto& f : rec.frames) {
            const auto res = ledger2.apply_block(BlockView(f));
            ASSERT_TRUE(res.ok) << res.error;
        }
        UndoEngine undo2(dir, store2, ledger2);
        EXPECT_TRUE(undo2.finalized_sidecar_trusted());
        EXPECT_EQ(undo2.finalized_checkpoint_height(), 20ull)
            << "the certified height was not restored from the sidecar";

        // Rollback BELOW the certified height: refused with the GQC error.
        EXPECT_FALSE(undo2.rollback_to_height(7));
        EXPECT_NE(undo2.last_error().find("ERR_FINALIZED_BY_GQC"),
                  std::string::npos)
            << "expected ERR_FINALIZED_BY_GQC, got: " << undo2.last_error();
        EXPECT_FALSE(undo2.rollback_to_height(19));
        EXPECT_NE(undo2.last_error().find("ERR_FINALIZED_BY_GQC"),
                  std::string::npos);

        // Rollback AT the certified height still works (only heights ABOVE
        // the checkpoint are unwound) and must land on the fresh prefix.
        ASSERT_TRUE(undo2.rollback_to_height(20)) << undo2.last_error();
        EXPECT_EQ(ledger2.next_expected_height(), 21ull);
        {
            LedgerState fresh_prefix;
            ASSERT_TRUE(
                fresh_prefix.apply_block(BlockView(rec.genesis_frame)).ok);
            for (uint64_t i = 0; i < 20; ++i) {
                ASSERT_TRUE(
                    fresh_prefix.apply_block(BlockView(rec.frames[i])).ok);
            }
            EXPECT_EQ(ledger2.total_supply(), fresh_prefix.total_supply());
            EXPECT_EQ(ledger2.issued_supply(), fresh_prefix.issued_supply());
            EXPECT_EQ(ledger2.total_burned(), fresh_prefix.total_burned());
            for (const auto& a : rec.touched) {
                EXPECT_EQ(ledger2.balance_of(a), fresh_prefix.balance_of(a));
                EXPECT_EQ(ledger2.get_next_nonce(a),
                          fresh_prefix.get_next_nonce(a));
            }
        }
        // Re-apply 21..24, then a second rollback ABOVE the checkpoint.
        for (uint64_t i = 20; i < 24; ++i) {
            undo2.apply_block(BlockView(rec.frames[i]));
            ASSERT_TRUE(ledger2.apply_block(BlockView(rec.frames[i])).ok);
        }
        ASSERT_TRUE(undo2.rollback_to_height(22)) << undo2.last_error();
        EXPECT_EQ(ledger2.next_expected_height(), 23ull);
    }

    std::filesystem::remove_all(dir);
}
