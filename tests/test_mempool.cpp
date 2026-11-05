#include <gtest/gtest.h>
#include "vx/state/mempool.hpp"
#include "vx/core/u128.hpp"

#include <atomic>
#include <cstring>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace {

vx::blockchain::Transaction make_tx(const char* sender, uint64_t amount,
                                    uint32_t fee, uint32_t nonce) {
    vx::blockchain::Transaction tx{};
    std::memset(tx.sender_nfa, 0, 42);
    std::memset(tx.receiver_nfa, 0, 42);
    std::memcpy(tx.sender_nfa, sender, std::min(std::strlen(sender), size_t(42)));
    std::memcpy(tx.receiver_nfa, "MEPOOL_TEST_RECV_000000000000000000000000", 42);
    vx::blockchain::tx_set_amount(tx, amount);
    vx::blockchain::tx_set_fee(tx, fee);
    vx::blockchain::tx_set_nonce(tx, nonce);
    // Admission gate (submit) verifies the cocoon proof first.
    vx::blockchain::sign_transaction(tx);
    return tx;
}

constexpr uint64_t kAmount = 2'000'000; // 0.02 VX: same amount for all txs
                                        // => entropy_cost equal => priority
                                        // is proportional to fee. Also above
                                        // the TDI dust threshold (1.12M atoms
                                        // minimum for a 112-byte tx).

constexpr uint32_t kSenderCount = 8;
constexpr uint32_t kTxsPerSender = 40;

std::string sender_name(uint32_t s) {
    std::string base = "MEMPOOL_STRESS_SENDER_00000000000000000000"; // 42 chars
    base[40] = static_cast<char>('0' + (s / 10) % 10);
    base[41] = static_cast<char>('0' + s % 10);
    return base;
}

} // namespace

TEST(VortexMempoolTest, StaticAssertGeometry) {
    static_assert(sizeof(vx::blockchain::RawBlock) == 65536, "RawBlock must be 64KB");
    static_assert(sizeof(vx::blockchain::BlockHeader) == 472, "BlockHeader must be 472 bytes");
    static_assert(sizeof(vx::blockchain::Transaction) == 112, "Transaction must be 112 bytes");
    static_assert(sizeof(vx::blockchain::VortexFrameTail) == 104, "VortexFrameTail must be 104 bytes");
}

TEST(VortexMempoolTest, MempoolConstruction) {
    vx::state::Mempool mempool;
    EXPECT_EQ(mempool.stats().count, 0);
    EXPECT_EQ(mempool.stats().byte_occupancy, 0);
}

// ── BACKLOG 0.14(a): the global fee sort must never invert a sender's
// nonce chain. Sender A has a low-fee nonce-0 and a high-fee nonce-1;
// sender B has one mid-fee tx. Under the old global sort the pull order
// was A1, B0, A0 — the sealed block failed apply with "nonce mismatch"
// and the miner dropped it with txs retained (repeatable livelock).
// Under the k-way chain merge the pull order is B0, A0, A1: B wins on
// priority, A's chain is emitted in nonce order regardless of fees.
TEST(VortexMempoolTest, SealingPreservesPerSenderNonceOrder) {
    vx::state::Mempool pool;
    const auto a0 = make_tx("MEMPOOL_ORDER_SENDER_A_00000000000000000", kAmount, 10, 0);
    const auto a1 = make_tx("MEMPOOL_ORDER_SENDER_A_00000000000000000", kAmount, 10000, 1);
    const auto b0 = make_tx("MEMPOOL_ORDER_SENDER_B_00000000000000000", kAmount, 500, 0);

    EXPECT_TRUE(pool.submit(a0, vx::core::U128(1'000'000'000), 0).ok);
    EXPECT_TRUE(pool.submit(a1, vx::core::U128(1'000'000'000), 0).ok);
    EXPECT_TRUE(pool.submit(b0, vx::core::U128(1'000'000'000), 0).ok);

    const auto pulled = pool.pull_for_sealing(10);
    ASSERT_EQ(pulled.size(), 3u);
    EXPECT_EQ(vx::blockchain::tx_nonce(pulled[0]), 0u); // B0 (best head)
    EXPECT_EQ(std::memcmp(pulled[0].sender_nfa, b0.sender_nfa, 42), 0);
    EXPECT_EQ(vx::blockchain::tx_nonce(pulled[1]), 0u); // A0 — NOT A1
    EXPECT_EQ(std::memcmp(pulled[1].sender_nfa, a0.sender_nfa, 42), 0);
    EXPECT_EQ(vx::blockchain::tx_nonce(pulled[2]), 1u); // A1 after A0
    EXPECT_EQ(std::memcmp(pulled[2].sender_nfa, a1.sender_nfa, 42), 0);
}

// A budget cut can split a sender's chain, but only at a nonce boundary:
// a high-fee nonce-1 must never be pulled while its nonce-0 is still
// pending, no matter how small the budget.
TEST(VortexMempoolTest, PullBudgetNeverBreaksSenderChain) {
    vx::state::Mempool pool;
    const auto a0 = make_tx("MEMPOOL_ORDER_SENDER_A_00000000000000000", kAmount, 10, 0);
    const auto a1 = make_tx("MEMPOOL_ORDER_SENDER_A_00000000000000000", kAmount, 10000, 1);
    const auto b0 = make_tx("MEMPOOL_ORDER_SENDER_B_00000000000000000", kAmount, 500, 0);
    EXPECT_TRUE(pool.submit(a0, vx::core::U128(1'000'000'000), 0).ok);
    EXPECT_TRUE(pool.submit(a1, vx::core::U128(1'000'000'000), 0).ok);
    EXPECT_TRUE(pool.submit(b0, vx::core::U128(1'000'000'000), 0).ok);

    auto pulled = pool.pull_for_sealing(1);
    ASSERT_EQ(pulled.size(), 1u);
    EXPECT_EQ(std::memcmp(pulled[0].sender_nfa, b0.sender_nfa, 42), 0); // best head
    pool.remove_sealed(pulled);

    pulled = pool.pull_for_sealing(1);
    ASSERT_EQ(pulled.size(), 1u);
    EXPECT_EQ(vx::blockchain::tx_nonce(pulled[0]), 0u); // A0, never A1-first
    pool.remove_sealed(pulled);

    pulled = pool.pull_for_sealing(1);
    ASSERT_EQ(pulled.size(), 1u);
    EXPECT_EQ(vx::blockchain::tx_nonce(pulled[0]), 1u); // A1 only after A0
    pool.remove_sealed(pulled);
    EXPECT_TRUE(pool.empty());
}

// Deterministic core of the acceptance criterion: N senders x M txs,
// pulled in partial batches, replay in pull order with a per-sender
// expected-nonce ledger simulation — every tx applies on first attempt
// (the ledger's nonce gate is exactly what inverted ordering used to trip).
TEST(VortexMempoolTest, SealedBatchesApplyOnFirstAttempt) {
    vx::state::Mempool pool;
    constexpr uint32_t kSenders = 5;
    constexpr uint32_t kPerSender = 20;
    constexpr uint64_t kBalance = 1'000'000'000;

    std::vector<vx::blockchain::Transaction> txs;
    for (uint32_t s = 0; s < kSenders; ++s) {
        std::mt19937 rng(0xC0FFEE + s);
        for (uint32_t m = 0; m < kPerSender; ++m) {
            const uint32_t fee = 10 + (rng() % 5000); // random fee landscape
            txs.push_back(make_tx(sender_name(s).c_str(), kAmount, fee, m));
        }
    }
    // Interleaved submission: per sender the nonces stay contiguous; the
    // pool holds all 100 txs afterwards.
    for (uint32_t m = 0; m < kPerSender; ++m) {
        for (uint32_t s = 0; s < kSenders; ++s) {
            const auto& tx = txs[s * kPerSender + m];
            const auto r = pool.submit(tx, vx::core::U128(kBalance), 0);
            ASSERT_TRUE(r.ok) << "sender " << s << " nonce " << m << ": " << r.error;
        }
    }
    EXPECT_EQ(pool.count(), kSenders * kPerSender);

    // Drain in partial batches and replay against per-sender nonce gates.
    std::vector<uint32_t> expected(kSenders, 0);
    std::set<std::pair<std::string, uint32_t>> seen;
    size_t total = 0;
    while (!pool.empty()) {
        const auto batch = pool.pull_for_sealing(7);
        ASSERT_FALSE(batch.empty());
        pool.remove_sealed(batch);
        for (const auto& tx : batch) {
            const std::string sender(reinterpret_cast<const char*>(tx.sender_nfa), 42);
            const uint32_t nonce = vx::blockchain::tx_nonce(tx);
            uint32_t idx = kSenders;
            for (uint32_t s = 0; s < kSenders; ++s)
                if (sender == sender_name(s)) idx = s;
            ASSERT_LT(idx, kSenders) << "unknown sender pulled";
            EXPECT_EQ(nonce, expected[idx])
                << "nonce gate would REJECT this tx in block apply";
            ++expected[idx];
            EXPECT_TRUE(seen.emplace(sender, nonce).second) << "duplicate pull";
            ++total;
        }
    }
    EXPECT_EQ(total, kSenders * kPerSender);
    EXPECT_EQ(seen.size(), kSenders * kPerSender);
}

// ── BACKLOG 0.14(b) acceptance: concurrent submitters + a concurrent
// sealing reader. Every pulled tx must be a fully-written entry (an
// unwritten default entry has a zeroed sender and cannot match any
// submitted tx), and every pull batch must keep each sender's nonce
// chain contiguous from the previously sealed prefix — so a concurrent
// reader never observes a torn or unwritten slot, and every pulled
// sequence applies on first attempt.
TEST(VortexMempoolTest, ConcurrentSubmitsAndSealsStayConsistent) {
    vx::state::Mempool pool;

    std::vector<std::vector<vx::blockchain::Transaction>> txs(kSenderCount);
    for (uint32_t s = 0; s < kSenderCount; ++s) {
        std::mt19937 rng(0xBEEF + s);
        for (uint32_t m = 0; m < kTxsPerSender; ++m) {
            txs[s].push_back(
                make_tx(sender_name(s).c_str(), kAmount, 10 + (rng() % 5000), m));
        }
    }

    std::atomic<uint32_t> accepted{0};
    std::atomic<bool> stop_reader{false};
    std::mutex batches_mutex;
    std::vector<std::vector<vx::blockchain::Transaction>> batches;
    std::atomic<uint64_t> stats_reads{0};

    // One submitter thread per sender: submits its own nonce chain in
    // order, retrying on a lost race (a rejected submit never stores).
    std::vector<std::thread> submitters;
    for (uint32_t s = 0; s < kSenderCount; ++s) {
        submitters.emplace_back([s, &txs, &pool, &accepted] {
            const uint64_t balance = 1'000'000'000;
            for (uint32_t m = 0; m < kTxsPerSender;) {
                const auto r = pool.submit(txs[s][m], vx::core::U128(balance), 0);
                if (r.ok) {
                    ++accepted;
                    ++m;
                } else {
                    std::this_thread::yield();
                }
            }
        });
    }

    // Sealing reader: pulls partial batches while submissions race in and
    // seals them (remove_sealed) exactly like the miner loop does.
    std::thread reader([&] {
        while (!stop_reader.load(std::memory_order_acquire)) {
            const auto batch = pool.pull_for_sealing(1 + (accepted.load() % 32));
            if (!batch.empty()) {
                pool.remove_sealed(batch);
                std::lock_guard<std::mutex> lk(batches_mutex);
                batches.push_back(batch);
            }
            ++stats_reads;
            const auto st = pool.stats(); // concurrent stats reader path
            (void)st;
            if (accepted.load(std::memory_order_acquire) >= kSenderCount * kTxsPerSender &&
                pool.empty()) {
                stop_reader.store(true, std::memory_order_release);
            }
        }
    });

    for (auto& t : submitters) t.join();
    reader.join();

    // Drain whatever the reader has not taken yet.
    while (!pool.empty()) {
        const auto batch = pool.pull_for_sealing(16);
        if (batch.empty()) break;
        pool.remove_sealed(batch);
        std::lock_guard<std::mutex> lk(batches_mutex);
        batches.push_back(batch);
    }

    // Verify every pulled batch: membership + per-sender chain order.
    ASSERT_EQ(accepted.load(), kSenderCount * kTxsPerSender);
    std::vector<uint32_t> sealed_prefix(kSenderCount, 0);
    std::set<std::pair<uint32_t, uint32_t>> seen;
    size_t total = 0;
    for (const auto& batch : batches) {
        // Within one pull batch, each sender's txs must be the NEXT
        // contiguous nonce window of that sender, in ascending order.
        std::vector<std::vector<uint32_t>> in_batch(kSenderCount);
        for (const auto& tx : batch) {
            uint32_t s = kSenderCount;
            for (uint32_t k = 0; k < kSenderCount; ++k) {
                if (std::memcmp(tx.sender_nfa, txs[k][0].sender_nfa, 42) == 0) { s = k; break; }
            }
            ASSERT_LT(s, kSenderCount)
                << "a pulled tx does not match any submitted tx"
                << " (torn or unwritten slot observed)";
            const uint32_t nonce = vx::blockchain::tx_nonce(tx);
            in_batch[s].push_back(nonce);
            EXPECT_TRUE(seen.emplace(s, nonce).second) << "tx pulled twice";
        }
        for (uint32_t s = 0; s < kSenderCount; ++s) {
            for (size_t i = 0; i < in_batch[s].size(); ++i) {
                EXPECT_EQ(in_batch[s][i], sealed_prefix[s] + static_cast<uint32_t>(i))
                    << "sender " << s << ": nonce chain broken within a batch";
            }
            sealed_prefix[s] += static_cast<uint32_t>(in_batch[s].size());
        }
        total += batch.size();
    }
    EXPECT_EQ(total, kSenderCount * kTxsPerSender);
    for (uint32_t s = 0; s < kSenderCount; ++s)
        EXPECT_EQ(sealed_prefix[s], kTxsPerSender) << "sender " << s << " not fully sealed";
    EXPECT_GT(stats_reads.load(), 0u);
}

// -- BACKLOG 0.10 (C1): per-sender pending cap --------------------------------
// One address may hold at most MEMPOOL_MAX_TXS_PER_SENDER (256) pending txs.
// Fees: nonces 0..254 pay 1000, nonce 255 pays 10 (the weakest tail), the
// extra nonce 256 pays 1000. The 257th submit triggers pressure relief: the
// pool evicts the sender's weakest entry (the fee-10 tail), rewinds the
// chain, and refuses the incoming tx -- a capped chain can never grow past
// the cap. Resubmitting the evicted nonce revalidates and is admitted; the
// cap holds afterwards.
TEST(VortexMempoolTest, PerSenderCapEnforced) {
    vx::state::Mempool pool;
    constexpr uint64_t kBalance = 2'000'000'000;
    constexpr uint32_t kCapTxs = 256; // == MEMPOOL_MAX_TXS_PER_SENDER

    auto fee_of = [](uint32_t nonce) { return nonce == 255 ? 10u : 1000u; };
    std::vector<vx::blockchain::Transaction> txs;
    for (uint32_t m = 0; m <= kCapTxs; ++m)
        txs.push_back(make_tx("MEMPOOL_CAP_SENDER_000000000000000000000", kAmount, fee_of(m), m));

    uint32_t accepted = 0;
    for (uint32_t m = 0; m < kCapTxs; ++m) {
        const auto r = pool.submit(txs[m], vx::core::U128(kBalance), 0);
        ASSERT_TRUE(r.ok) << "nonce " << m << ": " << r.error;
        ++accepted;
    }
    EXPECT_EQ(pool.count(), kCapTxs);

    // The 257th submit: weakest (fee-10) entry evicted, incoming refused.
    const auto r256 = pool.submit(txs[kCapTxs], vx::core::U128(kBalance), 0);
    EXPECT_FALSE(r256.ok);
    EXPECT_NE(r256.error.find("per-sender pending cap"), std::string::npos) << r256.error;
    EXPECT_EQ(pool.count(), kCapTxs - 1);

    // The evicted nonce revalidates and is admitted again.
    const auto r255 = pool.submit(txs[255], vx::core::U128(kBalance), 0);
    EXPECT_TRUE(r255.ok);
    EXPECT_EQ(pool.count(), kCapTxs);

    // The cap holds: no third nonce ever fits.
    const auto r256b = pool.submit(txs[kCapTxs], vx::core::U128(kBalance), 0);
    EXPECT_FALSE(r256b.ok);
    EXPECT_EQ(pool.count(), kCapTxs - 1);

    // Drain: the pull order still applies on first attempt (nonce gate) and
    // the pool never exposed more than the cap.
    std::vector<uint32_t> seen_nonces;
    while (!pool.empty()) {
        const auto batch = pool.pull_for_sealing(64);
        ASSERT_FALSE(batch.empty());
        pool.remove_sealed(batch);
        for (const auto& tx : batch) seen_nonces.push_back(vx::blockchain::tx_nonce(tx));
    }
    EXPECT_EQ(seen_nonces.size(), kCapTxs - 1);
    for (size_t i = 0; i < seen_nonces.size(); ++i)
        EXPECT_EQ(seen_nonces[i], i) << "nonce chain broken after cap eviction";
}

// -- BACKLOG 0.10 (C1): the eviction victim is the lowest fee density --------
// Fee layout: every nonce pays 1000 except nonce 3, which pays 10. When the
// capped sender pushes a 257th tx, the pool must evict exactly the weakest
// entry AND its nonce suffix (3..255): evicting a mid-chain nonce alone
// would strand the higher nonces behind a gap and reintroduce the 0.14
// nonce-mismatch livelock, so the suffix leaves with it. The high-fee
// prefix (0..2) and nothing else remains.
TEST(VortexMempoolTest, EvictLowestFeeUnderPressure) {
    vx::state::Mempool pool;
    constexpr uint64_t kBalance = 2'000'000'000;
    constexpr uint32_t kCapTxs = 256;

    auto fee_of = [](uint32_t nonce) { return nonce == 3 ? 10u : 1000u; };
    for (uint32_t m = 0; m < kCapTxs; ++m) {
        const auto tx = make_tx("MEMPOOL_EVICT_SENDER_00000000000000000000", kAmount, fee_of(m), m);
        const auto r = pool.submit(tx, vx::core::U128(kBalance), 0);
        ASSERT_TRUE(r.ok) << "nonce " << m << ": " << r.error;
    }
    EXPECT_EQ(pool.count(), kCapTxs);

    const auto extra = make_tx("MEMPOOL_EVICT_SENDER_00000000000000000000", kAmount, 1000, kCapTxs);
    const auto r = pool.submit(extra, vx::core::U128(kBalance), 0);
    EXPECT_FALSE(r.ok);

    // Only the fee-10 victim (nonce 3) and its suffix (4..255) are gone.
    EXPECT_EQ(pool.count(), 3u);
    const auto pulled = pool.pull_for_sealing(64);
    ASSERT_EQ(pulled.size(), 3u);
    for (size_t i = 0; i < pulled.size(); ++i)
        EXPECT_EQ(vx::blockchain::tx_nonce(pulled[i]), i) << "survivor set is exactly nonces 0..2";
}

// -- BACKLOG 0.10 (C1): an evicted tx can never be sealed --------------------
// Drain the pool in partial batches after a pressure eviction and replay it
// through per-sender nonce gates: the evicted tx must appear in NO pull
// batch, every pulled batch keeps the chain contiguous, and every pulled tx
// applies on first attempt.
TEST(VortexMempoolTest, EvictedTxNeverSealed) {
    vx::state::Mempool pool;
    constexpr uint64_t kBalance = 2'000'000'000;
    constexpr uint32_t kCapTxs = 256;
    constexpr uint32_t kVictimNonce = 255; // weakest tail (fee 10) -> evicted

    auto fee_of = [](uint32_t nonce) { return nonce == kVictimNonce ? 10u : 1000u; };
    std::vector<vx::blockchain::Transaction> txs;
    for (uint32_t m = 0; m < kCapTxs; ++m)
        txs.push_back(make_tx("MEMPOOL_NEVERSEAL_SENDER_000000000000000000", kAmount, fee_of(m), m));
    for (uint32_t m = 0; m < kCapTxs; ++m) {
        const auto r = pool.submit(txs[m], vx::core::U128(kBalance), 0);
        ASSERT_TRUE(r.ok) << "nonce " << m << ": " << r.error;
    }

    // Pressure: push a 257th tx -> the fee-10 tail is evicted, incoming
    // refused. The victim is gone from the pool when the call returns.
    const auto extra = make_tx("MEMPOOL_NEVERSEAL_SENDER_000000000000000000", kAmount, 1000, kCapTxs);
    EXPECT_FALSE(pool.submit(extra, vx::core::U128(kBalance), 0).ok);
    EXPECT_EQ(pool.count(), kCapTxs - 1);

    // Drain in small partial batches, like the miner loop does.
    std::set<std::pair<uint32_t, uint32_t>> seen; // (nonce, fee) of every pulled tx
    uint32_t expected_nonce = 0;
    while (!pool.empty()) {
        const auto batch = pool.pull_for_sealing(7);
        ASSERT_FALSE(batch.empty());
        pool.remove_sealed(batch);
        for (const auto& tx : batch) {
            const uint32_t nonce = vx::blockchain::tx_nonce(tx);
            EXPECT_EQ(nonce, expected_nonce)
                << "nonce gate would REJECT this tx in block apply";
            ++expected_nonce;
            EXPECT_TRUE(seen.emplace(nonce, tx.fee[3]).second) << "tx pulled twice";
        }
    }
    // The evicted victim never appeared in any pull.
    EXPECT_EQ(seen.count({kVictimNonce, 10}), 0u) << "evicted tx was sealed!";
    EXPECT_EQ(expected_nonce, kCapTxs - 1);
}
// Security-review fix (stage_C round 2, P1-1): the pull window. A tx pulled
// for sealing stays a valid pool entry until remove_sealed; an eviction in
// that window (global pressure from another sender) rewinds the sealed
// sender's pending nonce BELOW the nonce the chain is about to consume.
// Old behavior after the dust settled: remove_sealed found no entry to
// adjust, pending state stayed below the chain nonce, honest resubmissions
// were refused ("nonce mismatch") while stale nonces passed validation and
// wedged block apply — a livelock for the victim sender until restart.
// New behavior: remove_sealed advances every sealed sender's expected nonce
// monotonically from the sealed set itself (even entries the pool no longer
// holds), and admission has a chain-nonce floor as defense in depth.
TEST(VortexMempoolTest, PullWindowEvictionDoesNotRewindBelowChainNonce) {
    vx::state::Mempool pool;
    const auto a0 = make_tx("MEMPOOL_ORDER_SENDER_A_00000000000000000", kAmount, 10, 0);
    const auto a1 = make_tx("MEMPOOL_ORDER_SENDER_A_00000000000000000", kAmount, 10000, 1);
    const auto b0 = make_tx("MEMPOOL_ORDER_SENDER_B_00000000000000000", kAmount, 500, 0);
    EXPECT_TRUE(pool.submit(a0, vx::core::U128(1'000'000'000), 0).ok);
    EXPECT_TRUE(pool.submit(a1, vx::core::U128(1'000'000'000), 0).ok);
    EXPECT_TRUE(pool.submit(b0, vx::core::U128(1'000'000'000), 0).ok);

    // Seal pull: the three txs leave the pool logically but stay valid
    // entries until remove_sealed — the pull window.
    const auto pulled = pool.pull_for_sealing(10);
    ASSERT_EQ(pulled.size(), 3u);

    // Fill the pool to the hard cap with junk senders whose fees (600)
    // outrank A0 (fee 10), so the pulled A-chain is the globally weakest
    // work. The next submit under global pressure evicts A0 plus its nonce
    // suffix A1 and rewinds A's pending nonce to 0 — mid-pull-window. The
    // following junk submit evicts B0 the same way.
    auto junk_name = [](uint32_t s) {
        std::string name = "MEMPOOL_FLOOD_SENDER_"; // 21 chars
        name += std::to_string(s);
        return name;
    };
    bool a_chain_evicted = false;
    bool b0_evicted = false;
    for (uint32_t s = 0; s < vx::state::MEMPOOL_MAX_TXS + 4; ++s) {
        const bool was_full = (pool.count() >= vx::state::MEMPOOL_MAX_TXS);
        const auto j = make_tx(junk_name(s).c_str(), kAmount, 600, 0);
        const auto r = pool.submit(j, vx::core::U128(1'000'000'000), 0);
        if (was_full && r.ok) {
            // This submit only succeeded by evicting the globally weakest
            // work: the pulled A-chain first (fee 10), then B0 (fee 500).
            if (!a_chain_evicted) a_chain_evicted = true;
            else b0_evicted = true;
        }
        if (a_chain_evicted && b0_evicted) break;
    }
    ASSERT_TRUE(a_chain_evicted) << "global-pressure eviction never fired";
    ASSERT_TRUE(b0_evicted) << "second eviction target (B0) never fired";

    // The chain consumes the pulled nonces: remove_sealed must advance the
    // pending state monotonically even though the pool no longer holds the
    // evicted entries.
    pool.remove_sealed(pulled);

    // Make room (the junk flood still fills the pool to the cap) so the
    // resubmission checks below exercise the nonce gate, not "mempool full".
    const auto drained = pool.pull_for_sealing(64);
    pool.remove_sealed(drained);

    // The honest next nonce (2) is accepted again — the old bug refused it
    // because the rewound pending state said the expected nonce was 0.
    const auto a2 = make_tx("MEMPOOL_ORDER_SENDER_A_00000000000000000", kAmount, 10, 2);
    const auto res2 = pool.submit(a2, vx::core::U128(1'000'000'000), 2);
    EXPECT_TRUE(res2.ok) << "honest resubmit refused: " << res2.error;

    // The stale nonce (0, already sealed) is rejected — the old bug passed
    // it because the rewound pending state matched the stale nonce.
    const auto stale = make_tx("MEMPOOL_ORDER_SENDER_A_00000000000000000", kAmount, 10, 0);
    const auto res_stale = pool.submit(stale, vx::core::U128(1'000'000'000), 2);
    EXPECT_FALSE(res_stale.ok);
    EXPECT_NE(res_stale.error.find("nonce"), std::string::npos);
}
