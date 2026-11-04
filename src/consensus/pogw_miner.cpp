#include "vx/consensus/pogw_miner.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/blockchain/emission.hpp"
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
    // The search target IS the store's live-intake gate (BACKLOG 0.9): the
    // height-derived ASERT curve is the single source of difficulty truth.
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

    // Emission schedule (user-directed, hard-coded): the coinbase carries
    // the block's schedule reward - 50 VX guaranteed for any valid block,
    // up to 1,000 VX when the block's own hash carries 20/24/28/32/40
    // leading zero bits - plus the fee share, clamped to the issuance
    // headroom under the 7,000,000,000 VX supply cap (the final emission
    // blocks mint exactly the remainder, then the cap closes).
    const state::U128 issuance_headroom = ledger_.issuance_headroom();
    auto clamped = [&](state::U128 amount) {
        return amount > issuance_headroom ? issuance_headroom : amount;
    };

    // The coinbase amount is part of the hashed frame, so a reward claim
    // and the hash that justifies it must be searched TOGETHER: start at
    // the guaranteed floor; when the found hash carries more leading zeros
    // than the claim needs, raise the claim to the hash's actual tier and
    // search on - a higher claim demands a rarer hash, which is strictly
    // more PoGW work. A miner cannot mint the bonus, only find it.
    size_t claim_tier = 0; // 0 = the guaranteed floor; else index-1 into the tier tables
    auto claim_atoms = [&]() -> state::U128 {
        const uint64_t reward_vx =
            claim_tier == 0
                ? blockchain::BLOCK_REWARD_BASE_VX
                : blockchain::REWARD_TIER_VX[claim_tier - 1];
        return state::U128(reward_vx * blockchain::ATOMS_PER_VX) + miner_reward;
    };

    uint64_t nonce = 0;
    blockchain::BlockFrame frame;
    for (;;) {
        if (!running_.load()) return;

        // (Re)build the block with the current claim.
        blockchain::Transaction cb;
        coinbase_tx(cb, height, clamped(claim_atoms()), tip);

        blockchain::BlockBuilder final_builder;
        final_builder.set_height(height);
        final_builder.set_timestamp(std::chrono::system_clock::now().time_since_epoch().count() / 1000000000);
        final_builder.set_prev_hash(tip);
        final_builder.set_attractor_coords(coords);
        final_builder.add_transaction(cb); // index 0
        for (const auto& tx : txs) final_builder.add_transaction(tx);
        final_builder.finalize();
        auto frame_view = final_builder.bytes();

        // PoGW Search: find a 64-bit nonce whose VortexSponge256 frame hash
        // carries at least the claimed work - the network difficulty, and,
        // above the floor, the claimed tier's absolute zero-bit threshold.
        const uint64_t claim_bits =
            claim_tier == 0
                ? diff
                : std::max(diff, blockchain::REWARD_TIER_ZEROS[claim_tier - 1]);

        bool matched = false;
        uint8_t hash[32];
        while (running_.load()) {
            std::memcpy(frame.data(), frame_view.data(), 65536);
            auto* raw = reinterpret_cast<blockchain::RawBlock*>(frame.data());
            raw->tail.pogw_nonce = nonce;
            blockchain::VortexSponge256::compute(frame.data(), 65536, hash);

            bool match = true;
            for (uint64_t i = 0; i < (claim_bits / 8); ++i) {
                if (hash[i] != 0) { match = false; break; }
            }
            if (match && (claim_bits % 8 == 0 ||
                          (hash[claim_bits/8] & (0xFF << (8 - claim_bits % 8))) == 0)) {
                matched = true;
                break;
            }
            nonce++;

            // Check for stop every 100k nonces
            if ((nonce & 0xFFFF) == 0) {
                std::this_thread::yield();
            }
        }
        if (!matched) return; // stopped mid-search

        // Escalate: if the found hash is rarer than the claim needs, claim
        // its actual tier and keep searching (the escalated claim demands a
        // hash at that tier's threshold, so the entitlement always holds).
        const uint64_t zeros = blockchain::leading_zero_bits(hash);
        size_t actual_tier = 0;
        while (actual_tier < blockchain::REWARD_TIER_COUNT &&
               zeros >= blockchain::REWARD_TIER_ZEROS[actual_tier]) {
            ++actual_tier;
        }
        if (actual_tier > claim_tier) {
            claim_tier = actual_tier;
            continue;
        }

        // Commit results are no longer ignored (external review): a
        // rejected block must not drain the mempool or report success.
        // Round-7 hardening (P0-2): the state layer is only consulted
        // about a block that actually entered the store, and a block the
        // ledger refused is rolled back - a stuck "store ahead of
        // ledger" tip would wedge the miner and the RPC forever.
        const bool appended = store_.append_block(frame);
        if (appended) {
            const auto applied = ledger_.apply_block(
                blockchain::BlockView(std::span<const uint8_t, 65536>(frame.data(), 65536)));
            if (!applied.ok) {
                store_.rollback_last_append();
                std::cerr << "[MINER] Block #" << height << " REJECTED"
                          << " (applied=" << applied.ok
                          << (applied.error.empty() ? "" : (std::string(": ") + applied.error))
                          << "); sealed transactions kept in mempool\n";
                return;
            }
        } else {
            std::cerr << "[MINER] Block #" << height << " REJECTED (append failed)"
                      << "; sealed transactions kept in mempool\n";
            return;
        }

        // Remove sealed transactions from mempool
        mempool_.remove_sealed(txs);

        std::cout << "[MINER] Block #" << height << " mined with nonce " << nonce
                  << " diff " << diff << " reward "
                  << (claim_tier == 0 ? blockchain::BLOCK_REWARD_BASE_VX
                                      : blockchain::REWARD_TIER_VX[claim_tier - 1])
                  << " VX\n";
        return;
    }
}

uint64_t PoGWMiner::calculate_difficulty() const {
    // Single difficulty curve (found 2026-11-04, security review of the
    // ASERT retarget): the previous float-based time heuristic carried a
    // hardcoded anchor (16) and tau in seconds — a different curve in
    // different units from the real retarget. The height-derived store gate
    // is the one curve; the miner must aim exactly where the gate checks.
    return store_.required_pogw_bits();
}

void PoGWMiner::coinbase_tx(blockchain::Transaction& tx, uint64_t height, const state::U128& miner_reward,
                            const uint8_t prev_tip_hash[32]) {
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
    // BACKLOG 0.6 remainder closed: the coinbase commits its chain position
    // (receiver + height + previous tip hash) instead of the keyless digest.
    blockchain::set_coinbase_binding(tx, height, prev_tip_hash);
}

PoGWMiner::Status PoGWMiner::get_status() const {
    return {calculate_difficulty(), running_.load(), 0};
}

} // namespace vx::consensus