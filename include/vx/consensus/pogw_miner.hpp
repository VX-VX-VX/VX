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
    void mine_one(); // Sync call to mine one block

    struct Status {
        uint64_t difficulty;
        bool mining;
        uint64_t hash_rate;
    };
    Status get_status() const;

private:
    void mining_loop();
    uint64_t calculate_difficulty() const;
    void coinbase_tx(blockchain::Transaction& tx, uint64_t height, const state::U128& miner_reward);

    storage::BlockStore& store_;
    state::LedgerState& ledger_;
    state::Mempool& mempool_;

    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex mtx_;
    std::condition_variable cv_;
    uint64_t target_block_time_ = 5; // seconds
};

} // namespace vx::consensus
