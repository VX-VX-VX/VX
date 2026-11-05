#pragma once

#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/state/mempool.hpp"
#include <atomic>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>

namespace vx::consensus {

class PoGWMiner {
public:
    PoGWMiner(storage::BlockStore& store, state::LedgerState& ledger, state::Mempool& mempool);
    ~PoGWMiner();

    void start();
    void stop();

    // Mine one block from the current mempool contents (synchronous).
    // Background loop: mine_one() with the default. Single-shot: mine_one(true)
    // runs the SAME sealing flow exactly once from a caller that does not
    // keep the background loop running (RPC transfer / mempool seal path) -
    // the running_ guards inside the search pass when single_shot is set.
    void mine_one(bool single_shot = false);

    struct Status {
        uint64_t difficulty;
        bool mining;
        uint64_t hash_rate;
    };
    Status get_status() const;

private:
    void mining_loop();
    // The height-derived ASERT gate (store). Single difficulty curve.
    uint64_t calculate_difficulty() const;
    void coinbase_tx(blockchain::Transaction& tx, uint64_t height, const state::U128& miner_reward,
                     const uint8_t prev_tip_hash[32]);

    storage::BlockStore& store_;
    state::LedgerState& ledger_;
    state::Mempool& mempool_;

    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex mtx_;
    std::condition_variable cv_;
    // Serializes concurrent sealing (background loop vs a synchronous
    // single-shot caller): two miners building from the same tip would only
    // race to a failed append, but serializing keeps one writer.
    std::mutex seal_mutex_;
    uint64_t target_block_time_ = 5; // seconds
};

} // namespace vx::consensus
