#include "vx/consensus/pogw_miner.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include <iostream>
#include <chrono>
#include <algorithm>
#include <atomic>
#include <thread>
#include <vector>
#include <cmath>

namespace vx::consensus {

PoGWMiner::PoGWMiner(storage::BlockStore& store, state::LedgerState& ledger, state::Mempool& mempool)
    : store_(store), ledger_(ledger), mempool_(mempool) {}

PoGWMiner::~PoGWMiner() { stop(); }

void PoGWMiner::start() {
    running_.store(true);
    worker_ = std::thread(&PoGWMiner::mining_loop, this);
}

void PoGWMiner::stop() {
    if (running_.exchange(false)) {
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }
}

void PoGWMiner::mining_loop() {
    while (running_.load()) {
        mine_one();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void PoGWMiner::mine_one() {
    uint64_t height = store_.chain_height();
    uint64_t diff = calculate_difficulty();

    uint8_t tip[32];
    store_.tip_hash(tip);

    // Attractor coordinates from tip
    uint8_t coords[384];
    if (height > 0) {
        auto* raw = store_.get_block(height - 1);
        if (raw) {
            std::memcpy(coords, raw->header.attractor_coords, 384);
        } else {
            std::memset(coords, 0, 384);
        }
    } else {
        std::memset(coords, 0, 384);
    }

    // Pull from mempool (up to 579, leaving room for coinbase at index 0)
    auto txs = mempool_.pull_for_sealing(579);

    // Coinbase reward (deterministic emission calculation)
    // 50% fees to miner, 50% burned
    state::U128 total_fees{0};
    for(const auto& tx : txs) total_fees = total_fees + state::U128(blockchain::tx_fee(tx));
    state::U128 miner_reward = total_fees / state::U128(2); // 50% of fees

    // Add coinbase as first transaction (index 0)
    blockchain::Transaction cb;
    coinbase_tx(cb, height, miner_reward);

    // Build block
    blockchain::BlockBuilder final_builder;
    final_builder.set_height(height);
    final_builder.set_timestamp(std::chrono::system_clock::now().time_since_epoch().count() / 1000000000);
    final_builder.set_prev_hash(tip);
    final_builder.set_attractor_coords(coords);
    final_builder.add_transaction(cb); // index 0
    for (const auto& tx : txs) final_builder.add_transaction(tx);
    final_builder.finalize();

    // PoGW Search: find 64-bit nonce such that VortexSponge256 hash has leading zero bits >= target_difficulty_bits
    uint64_t nonce = 0;
    blockchain::BlockFrame frame;
    auto frame_view = final_builder.bytes();

    while (running_.load()) {
        std::memcpy(frame.data(), frame_view.data(), 65536);
        auto* raw = reinterpret_cast<blockchain::RawBlock*>(frame.data());
        raw->tail.pogw_nonce = nonce;

        uint8_t hash[32];
        blockchain::VortexSponge256::compute(frame.data(), 65536, hash);

        // Difficulty check: leading zero bits
        bool match = true;
        for (uint64_t i = 0; i < (diff / 8); ++i) {
            if (hash[i] != 0) { match = false; break; }
        }
        if (match && (diff % 8 == 0 || (hash[diff/8] & (0xFF << (8 - diff % 8))) == 0)) {
            store_.append_block(frame);
            ledger_.apply_block(blockchain::BlockView(std::span<const uint8_t, 65536>(frame.data(), 65536)));

            // Remove sealed transactions from mempool
            mempool_.remove_sealed(txs);

            std::cout << "[MINER] Block #" << height << " mined with nonce " << nonce << " diff " << diff << "\n";
            break;
        }
        nonce++;

        // Check for stop every 100k nonces
        if ((nonce & 0xFFFF) == 0) {
            std::this_thread::yield();
        }
    }
}

uint64_t PoGWMiner::calculate_difficulty() const {
    // ASERT difficulty adjustment: D_h = D_{h-1} * 2^((t_target - t_solve)/tau)
    // target = 5 seconds dev mode, tau = 130 (half-life)
    if (store_.chain_height() <= 1) return 16; // Genesis difficulty

    auto* prev_block = store_.get_block(store_.chain_height() - 1);
    if (!prev_block) return 16;

    uint64_t prev_difficulty = 16; // Could store in tail

    uint64_t prev_timestamp = prev_block->header.timestamp;
    uint64_t current_timestamp = std::chrono::system_clock::now().time_since_epoch().count() / 1000000000;
    int64_t solve_time = static_cast<int64_t>(current_timestamp - prev_timestamp);

    // ASERT: diff_new = diff_prev * 2^((target_time - solve_time) / tau)
    // target_time = 5 seconds, tau = 130 (half-life for ASERT)
    double target_time = 5.0;
    double tau = 130.0;
    double exponent = (target_time - static_cast<double>(solve_time)) / tau;

    double new_diff_double = static_cast<double>(prev_difficulty) * std::pow(2.0, exponent);
    uint64_t new_diff = static_cast<uint64_t>(std::max(1.0, std::min(new_diff_double, 256.0)));

    return new_diff;
}

void PoGWMiner::coinbase_tx(blockchain::Transaction& tx, uint64_t height, const state::U128& miner_reward) {
    std::memset(&tx, 0, sizeof(tx));
    const char* tag = "MINER_";
    std::memcpy(tx.sender_nfa, tag, 6);
    for (size_t i = 6; i < 42; ++i) tx.sender_nfa[i] = '0';

    // Miner reward address (use attractor-derived address for miner)
    // For now, use a fixed miner address
    static const char* miner_addr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    std::memcpy(tx.receiver_nfa, miner_addr, 42);

    blockchain::tx_set_amount(tx, miner_reward.lo);
    blockchain::tx_set_fee(tx, 0);
    blockchain::tx_set_nonce(tx, 0);
    blockchain::sign_transaction(tx);
}

PoGWMiner::Status PoGWMiner::get_status() const {
    return {calculate_difficulty(), running_.load(), 0};
}

} // namespace vx::consensus