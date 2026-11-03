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