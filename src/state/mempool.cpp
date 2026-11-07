#include "vx/state/mempool.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/simd_accel.hpp"
#include "vx/math/tdi_filter.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <unordered_map>

namespace vx::state {

using blockchain::Address;
using blockchain::Transaction;
using core::U128;

static Address tx_address(const uint8_t raw[42]) noexcept {
    Address a;
    std::memcpy(a.data(), raw, 42);
    return a;
}

static uint64_t tx_amount_local(const Transaction& tx) noexcept {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | tx.amount[i];
    return v;
}

static uint32_t tx_fee_local(const Transaction& tx) noexcept {
    uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | tx.fee[i];
    return v;
}

static uint32_t tx_nonce_local(const Transaction& tx) noexcept {
    uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | tx.nonce[i];
    return v;
}


bool Mempool::validate_pending_locked(const Transaction& tx, const U128& sender_balance, uint32_t sender_nonce) const noexcept {
    Address sender = tx_address(tx.sender_nfa);
    uint64_t amount = tx_amount_local(tx);
    uint32_t fee = tx_fee_local(tx);
    uint32_t nonce = tx_nonce_local(tx);

    // Check nonce
    auto nonce_it = pending_nonces_.find(sender);
    uint32_t expected_nonce = (nonce_it == pending_nonces_.end()) ? sender_nonce : nonce_it->second;

    // Chain-nonce floor (security-review P1-1, defense in depth): a nonce
    // the chain already consumed is stale no matter what the pending map
    // says — pending state can be briefly rewound by an eviction inside the
    // seal pull-window. Accepting a stale nonce would re-seal an applied tx
    // and wedge block apply.
    if (nonce < sender_nonce) {
        return false;
    }

    if (nonce != expected_nonce) {
        return false;
    }

    // Check balance (amount + fee)
    U128 total_cost = U128(amount) + U128(fee);
    auto pending_it = pending_outgoing_.find(sender);
    U128 pending_out = (pending_it == pending_outgoing_.end()) ? U128{0} : pending_it->second;

    if (sender_balance < total_cost + pending_out) {
        return false;
    }

    return true;
}

double Mempool::compute_priority(const Transaction& tx) const noexcept {
    uint32_t fee = tx_fee_local(tx);
    uint64_t amount = tx_amount_local(tx);

    // TDI fee-entropy density: fee / entropy_cost
    // entropy_cost approximates the "thermodynamic cost" of the transaction
    // Using a simplified model: entropy_cost = log2(amount + 1) * 1000 + 100
    // This gives higher priority to transactions with high fee relative to their size/entropy

    double entropy_cost = 100.0;
    if (amount > 0) {
        entropy_cost = std::log2(static_cast<double>(amount) + 1.0) * 1000.0 + 100.0;
    }

    double fee_double = static_cast<double>(fee);
    return fee_double / entropy_cost;
}

SubmitResult Mempool::submit(const Transaction& tx, const U128& sender_balance, uint32_t sender_nonce) {
    SubmitResult result;

    // 1. Verify cryptographic proof
    if (!blockchain::verify_transaction_proof(tx)) {
        result.error = "invalid cocoon_proof";
        return result;
    }

    // 2. Check TDI (Thermodynamic Invariant)
    uint64_t amount = tx_amount_local(tx);
    double amount_vx = static_cast<double>(amount) / 1e8;
    auto tdi = vx::math::TdiFilter::evaluate(112, amount_vx);
    if (tdi.isAnnihilated) {
        result.error = "TDI violation: " + tdi.reason;
        return result;
    }

    // 3..7: ONE critical section. Validation and the pending-state update
    // are atomic together — two concurrent submits of the same nonce can
    // no longer both pass the check before either reserves (TOCTOU fix).
    std::lock_guard<std::mutex> pending_lock(pending_mutex_);
    if (!validate_pending_locked(tx, sender_balance, sender_nonce)) {
        result.error = "nonce mismatch or insufficient balance (including pending)";
        return result;
    }

    // 3b. BACKLOG 0.10 pressure relief.
    //
    // Per-sender cap: the sender already holds MEMPOOL_MAX_TXS_PER_SENDER
    // pending txs. Evict that sender's weakest suffix (lowest fee density,
    // oldest admitted tie-break) so capacity is freed, then re-validate the
    // incoming tx against the rewound chain. Because the rewound expected
    // nonce is always BELOW the incoming next nonce, the incoming tx is
    // refused; the wallet resubmits from the rewound expected nonce. The
    // eviction - not the acceptance - is the point: a capped sender cannot
    // grow its pending chain past the cap, and its weakest work is dropped.
    Address sender = tx_address(tx.sender_nfa);
    {
        auto pc = pending_counts_.find(sender);
        if (pc != pending_counts_.end() && pc->second >= MEMPOOL_MAX_TXS_PER_SENDER) {
            const size_t victim = find_worst_sender_slot_locked(sender);
            if (victim != SIZE_MAX) evict_suffix_locked(victim);
            if (!validate_pending_locked(tx, sender_balance, sender_nonce)) {
                result.error = "per-sender pending cap reached (256); weakest pending tx evicted, resubmit from the expected nonce";
                return result;
            }
        }
    }

    // 4. Claim the next slot. BACKLOG 0.14(b): slot claim, entry write and
    // count publication all happen under the pool mutex, with the entry
    // fully written BEFORE the count moves. The old find_slot() CAS bumped
    // count_ first, so a concurrent reader could observe the bumped count
    // and read a not-yet-written (default) entry.
    size_t slot = count_.load(std::memory_order_relaxed);
    if (slot >= MEMPOOL_MAX_TXS) {
        // Global pressure: the pool is at its hard cap. Evict the globally
        // weakest entry (lowest fee density, oldest tie-break) only when the
        // incoming tx outranks it - otherwise reject the incoming tx: the
        // fee market must not churn the pool for work it ranks below.
        const double incoming_priority = compute_priority(tx);
        const size_t victim = find_worst_global_slot_locked(&sender);
        if (victim == SIZE_MAX || !(incoming_priority > entries_[victim].priority)) {
            result.error = "mempool full (16,384 tx limit)";
            return result;
        }
        evict_suffix_locked(victim);
        slot = count_.load(std::memory_order_relaxed);
        if (slot >= MEMPOOL_MAX_TXS) {
            result.error = "mempool full (16,384 tx limit)";
            return result;
        }
    }

    // 5. Compute priority
    double priority = compute_priority(tx);
    uint32_t fee = tx_fee_local(tx);
    uint32_t nonce = tx_nonce_local(tx);

    // 6. Insert entry (complete before it becomes visible via count_)
    Entry& entry = entries_[slot];
    entry.tx = tx;
    entry.fee = U128(fee);
    entry.amount = U128(amount);
    entry.priority = priority;
    entry.sender_nonce = nonce;
    entry.valid = true;
    count_.store(slot + 1, std::memory_order_release);

    // 7. Update pending state (same critical section as step 3)
    pending_outgoing_[sender] = pending_outgoing_[sender] + U128(amount + fee);
    pending_nonces_[sender] = nonce + 1;
    ++pending_counts_[sender];

    result.ok = true;
    result.position = slot;
    result.projected_height = 0; // Will be set by caller
    return result;
}

// -- Eviction (BACKLOG 0.10) --------------------------------------------------
// All three helpers REQUIRE pending_mutex_ to be held: they are called from
// submit() inside its single critical section, so eviction, pending-state
// rewind, compaction and the count update are atomic with respect to every
// other mutation (0.14 discipline).

size_t Mempool::find_worst_sender_slot_locked(const Address& sender) const noexcept {
    const size_t cnt = count_.load(std::memory_order_relaxed);
    size_t worst = SIZE_MAX;
    for (size_t i = 0; i < cnt; ++i) {
        if (!entries_[i].valid) continue;
        if (std::memcmp(entries_[i].tx.sender_nfa, sender.data(), 42) != 0) continue;
        // Strict '<' keeps the EARLIEST slot on equal priority = oldest
        // admitted, the documented tie-break.
        if (worst == SIZE_MAX || entries_[i].priority < entries_[worst].priority)
            worst = i;
    }
    return worst;
}

size_t Mempool::find_worst_global_slot_locked(const Address* exclude_sender) const noexcept {
    const size_t cnt = count_.load(std::memory_order_relaxed);
    size_t worst = SIZE_MAX;
    for (size_t i = 0; i < cnt; ++i) {
        if (!entries_[i].valid) continue;
        // Zero-trust review P1-2: never select the incoming sender's own
        // entries as the global-pressure victim. evict_suffix_locked rewinds
        // the WHOLE later-nonce chain of the victim's sender, but the
        // incoming tx was validated against the pre-eviction pending state;
        // evicting its own chain can strand the incoming nonce above the
        // rewound expected nonce (a pending nonce hole that block-apply
        // cannot drain — a seal-time livelock).
        if (exclude_sender &&
            std::memcmp(entries_[i].tx.sender_nfa, exclude_sender->data(), 42) == 0)
            continue;
        if (worst == SIZE_MAX || entries_[i].priority < entries_[worst].priority)
            worst = i;
    }
    return worst;
}

void Mempool::evict_suffix_locked(size_t victim_slot) noexcept {
    const size_t cnt = count_.load(std::memory_order_relaxed);
    if (victim_slot >= cnt || !entries_[victim_slot].valid) return;

    const Address sender = tx_address(entries_[victim_slot].tx.sender_nfa);
    const uint32_t victim_nonce = entries_[victim_slot].sender_nonce;
    size_t prior_count = 0;
    if (const auto pc = pending_counts_.find(sender); pc != pending_counts_.end())
        prior_count = pc->second;

    // Evict the victim and every later-nonce entry of the same sender.
    // Compaction preserves admission order, so same-sender entries at slots
    // >= victim_slot are exactly the sender's nonces >= victim_nonce (the
    // nonce < victim_nonce guard is a defensive invariant check, not logic).
    size_t evicted = 0;
    for (size_t i = victim_slot; i < cnt; ++i) {
        if (!entries_[i].valid) continue;
        if (std::memcmp(entries_[i].tx.sender_nfa, sender.data(), 42) != 0) continue;
        if (entries_[i].sender_nonce < victim_nonce) continue;

        const U128 cost = entries_[i].amount + entries_[i].fee;
        auto out_it = pending_outgoing_.find(sender);
        if (out_it != pending_outgoing_.end()) {
            if (out_it->second >= cost) {
                out_it->second = out_it->second - cost;
            } else {
                // The reserve is below the entry's cost: books have drifted.
                // Clamp (fail-safe) but say so — silent under-reserve would
                // let validate_pending admit submits against earmarked
                // funds and resurface as seal-time apply failures.
                std::fputs("mempool: pending_outgoing_ underflow (invariant violation)\n",
                           stderr);
                out_it->second = U128{0};
            }
            if (out_it->second.is_zero()) pending_outgoing_.erase(out_it);
        }
        entries_[i].valid = false;
        ++evicted;
    }
    if (evicted == 0) return;

    const size_t remaining = (prior_count > evicted) ? (prior_count - evicted) : 0;
    if (remaining == 0) {
        pending_nonces_.erase(sender);
        pending_counts_.erase(sender);
    } else {
        // The chain now ends just below the victim: the next expected nonce
        // is the victim's nonce, so a resubmission of it revalidates.
        pending_nonces_[sender] = victim_nonce;
        pending_counts_[sender] = remaining;
    }

    // Compact the array (move valid entries to front), same pass as
    // remove_sealed, then publish the new count.
    size_t write_idx = 0;
    for (size_t i = 0; i < cnt; ++i) {
        if (entries_[i].valid) {
            if (write_idx != i) entries_[write_idx] = entries_[i];
            ++write_idx;
        }
    }
    count_.store(write_idx, std::memory_order_release);
}

MempoolStats Mempool::stats() const noexcept {
    MempoolStats s;
    // Snapshot under the pool mutex: an unlocked scan over entries_ raced
    // with submit/remove_sealed (BACKLOG 0.14b).
    std::lock_guard<std::mutex> lock(pending_mutex_);
    size_t cnt = count_.load(std::memory_order_relaxed);
    s.count = cnt;
    s.byte_occupancy = cnt * 112;
    s.utilization_pct =
        (static_cast<double>(cnt) / static_cast<double>(blockchain::MAX_TX_PER_BLOCK)) *
        100.0; // full 64KB frame

    U128 total_fees{0};
    U128 total_amounts{0};
    for (size_t i = 0; i < cnt; ++i) {
        if (entries_[i].valid) {
            total_fees = total_fees + entries_[i].fee;
            total_amounts = total_amounts + entries_[i].amount;
        }
    }
    s.total_pending_fees = total_fees;
    s.total_pending_amounts = total_amounts;
    return s;
}

std::vector<Transaction> Mempool::pull_for_sealing(size_t max_count) noexcept {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    size_t cnt = count_.load(std::memory_order_relaxed);
    if (cnt == 0 || max_count == 0) return {};

    // ── BACKLOG 0.14(a): per-sender nonce chains.
    //
    // The old ordering was a single global fee sort with a GLOBAL nonce
    // tie-break: a sender's high-fee nonce-1 tx sorted ahead of its own
    // low-fee nonce-0 tx, the sealed block failed apply with "nonce
    // mismatch", the miner dropped it with txs retained — a repeatable
    // livelock under load.
    //
    // New ordering: group the pool into per-sender chains (admission makes
    // each sender's stored nonces contiguous from its expected nonce), then
    // k-way merge — the chain whose HEAD tx has the best priority wins the
    // next slot. Cross-sender, the fee market still rules; within a sender,
    // ascending nonce order is inviolable, so a nonce-k tx can never enter
    // a block without every lower nonce of the same sender.
    struct Chain {
        std::vector<const Entry*> txs; // ascending nonce
    };
    std::unordered_map<Address, size_t, AddressHash> chain_of;
    std::vector<Chain> chains;
    chains.reserve(cnt);
    for (size_t i = 0; i < cnt; ++i) {
        if (!entries_[i].valid) continue;
        const Address sender = tx_address(entries_[i].tx.sender_nfa);
        auto it = chain_of.find(sender);
        if (it == chain_of.end()) {
            it = chain_of.emplace(sender, chains.size()).first;
            chains.emplace_back();
        }
        chains[it->second].txs.push_back(&entries_[i]);
    }
    for (auto& ch : chains) {
        std::sort(ch.txs.begin(), ch.txs.end(), [](const Entry* a, const Entry* b) {
            if (a->sender_nonce != b->sender_nonce)
                return a->sender_nonce < b->sender_nonce;
            // Same sender + same nonce cannot pass admission; byte order
            // keeps the comparator total and deterministic regardless.
            return std::memcmp(&a->tx, &b->tx, sizeof(Transaction)) < 0;
        });
    }

    // K-way merge over chain heads. Comparator uses EXACT priority
    // comparison: compute_priority is a pure function of the tx bytes, so
    // equal fees/amounts yield exactly equal doubles on every node. (The
    // old epsilon tie-break — |a-b| > 1e-9 — was not a strict weak
    // ordering: intransitive ties are the classic std::sort UB pattern.)
    struct Head {
        const Entry* entry;
        size_t chain;
        size_t pos; // index of `entry` within chains[chain].txs
    };
    const auto head_worse = [](const Head& a, const Head& b) {
        // Max-heap "less": true when a ranks below b.
        if (a.entry->priority != b.entry->priority)
            return a.entry->priority < b.entry->priority;
        if (a.entry->sender_nonce != b.entry->sender_nonce)
            return a.entry->sender_nonce > b.entry->sender_nonce;
        const int c = std::memcmp(a.entry->tx.sender_nfa, b.entry->tx.sender_nfa, 42);
        if (c != 0) return c > 0;
        return std::memcmp(&a.entry->tx, &b.entry->tx, sizeof(Transaction)) > 0;
    };
    std::vector<Head> heap;
    heap.reserve(chains.size());
    for (size_t c = 0; c < chains.size(); ++c)
        heap.push_back({chains[c].txs.front(), c, 0});
    std::make_heap(heap.begin(), heap.end(), head_worse);

    std::vector<Transaction> result;
    result.reserve(std::min(max_count, cnt));
    while (!heap.empty() && result.size() < max_count) {
        std::pop_heap(heap.begin(), heap.end(), head_worse);
        const Head best = heap.back();
        heap.pop_back();
        result.push_back(best.entry->tx);
        const auto& ch = chains[best.chain];
        if (best.pos + 1 < ch.txs.size()) {
            heap.push_back({ch.txs[best.pos + 1], best.chain, best.pos + 1});
            std::push_heap(heap.begin(), heap.end(), head_worse);
        }
    }
    return result;
}

void Mempool::remove_sealed(const std::vector<Transaction>& sealed_txs) noexcept {
    // Create a set of sealed transaction hashes for O(1) lookup
    // We use sender + nonce as unique identifier
    struct SealedKey {
        Address sender;
        uint32_t nonce;
        bool operator==(const SealedKey& other) const noexcept {
            return nonce == other.nonce && std::memcmp(sender.data(), other.sender.data(), 42) == 0;
        }
    };

    struct KeyHash {
        size_t operator()(const SealedKey& k) const noexcept {
            size_t h = 1469598103934665603ull;
            for (uint8_t b : k.sender) {
                h ^= b;
                h *= 1099511628211ull;
            }
            return h ^ (k.nonce + 0x9e3779b9 + (h << 6) + (h >> 2));
        }
    };

    std::unordered_set<SealedKey, KeyHash> sealed_set;
    sealed_set.reserve(sealed_txs.size());

    for (const auto& tx : sealed_txs) {
        SealedKey key{tx_address(tx.sender_nfa), tx_nonce_local(tx)};
        sealed_set.insert(key);
    }

    // BACKLOG 0.14(b): the whole pass — invalidation, pending-state
    // adjustment, compaction and the count update — is ONE critical
    // section. The old code released the mutex before compacting, so a
    // concurrent submit could claim a slot above the snapshot count and
    // then be silently dropped by the count_.exchange(write_idx) below —
    // an accepted tx vanishing while its pending balance/nonce stayed
    // reserved (stuck sender until restart).
    std::lock_guard<std::mutex> lock(pending_mutex_);
    const size_t cnt = count_.load(std::memory_order_relaxed);
    for (size_t i = 0; i < cnt; ++i) {
        if (entries_[i].valid) {
            SealedKey key{tx_address(entries_[i].tx.sender_nfa), entries_[i].sender_nonce};
            if (sealed_set.find(key) != sealed_set.end()) {
                // Found sealed transaction - invalidate and adjust pending state
                Address sender = tx_address(entries_[i].tx.sender_nfa);
                uint64_t amount = tx_amount_local(entries_[i].tx);
                uint32_t fee = tx_fee_local(entries_[i].tx);

                // Subtract from pending outgoing
                auto pending_it = pending_outgoing_.find(sender);
                if (pending_it != pending_outgoing_.end()) {
                    if (pending_it->second >= U128(amount + fee)) {
                        pending_it->second = pending_it->second - U128(amount + fee);
                    } else {
                        // Books drifted below the sealed cost: clamp fail-safe
                        // but keep the invariant violation visible (see the
                        // twin clamp in evict_suffix_locked).
                        std::fputs("mempool: pending_outgoing_ underflow (invariant violation)\n",
                                   stderr);
                        pending_it->second = U128{0};
                    }
                    if (pending_it->second.is_zero()) {
                        pending_outgoing_.erase(pending_it);
                    }
                }

                // Reset pending nonce to the next expected value (monotone:
                // a lower out-of-order entry must never rewind the floor).
                {
                    const uint32_t want = entries_[i].sender_nonce + 1;
                    auto& cur = pending_nonces_[sender];
                    if (cur < want) cur = want;
                }

                // BACKLOG 0.10: keep the per-sender pending count consistent
                auto pc = pending_counts_.find(sender);
                if (pc != pending_counts_.end()) {
                    if (pc->second > 0) --pc->second;
                    if (pc->second == 0) pending_counts_.erase(pc);
                }

                // Invalidate entry
                entries_[i].valid = false;
            }
        }
    }

    // Security-review fix (stage_C round 2, P1-1): a tx pulled for sealing
    // but evicted before remove_sealed (the pull window) leaves NO entry to
    // adjust, yet the chain just consumed its nonce. Advance every sealed
    // sender's expected nonce to at least max(sealed nonce)+1 even when the
    // pool no longer holds the entry — the eviction rewound pending state
    // must never end up BELOW the chain nonce, or honest resubmissions are
    // refused while stale nonces pass and wedge block apply.
    for (const auto& key : sealed_set) {
        const uint32_t want = key.nonce + 1;
        auto pn = pending_nonces_.find(key.sender);
        if (pn == pending_nonces_.end()) {
            pending_nonces_[key.sender] = want;
        } else if (pn->second < want) {
            pn->second = want;
        }
    }

    // Compact the array (move valid entries to front)
    size_t write_idx = 0;
    for (size_t i = 0; i < cnt; ++i) {
        if (entries_[i].valid) {
            if (write_idx != i) {
                entries_[write_idx] = entries_[i];
            }
            ++write_idx;
        }
    }

    // Update count
    count_.store(write_idx, std::memory_order_release);
}

void Mempool::clear() noexcept {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    pending_outgoing_.clear();
    pending_nonces_.clear();
    pending_counts_.clear();

    const size_t cnt = count_.load(std::memory_order_relaxed);
    for (size_t i = 0; i < cnt; ++i) {
        entries_[i].valid = false;
    }
    count_.store(0, std::memory_order_release);
}

uint32_t Mempool::get_next_nonce(const Address& a) const noexcept {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    auto it = pending_nonces_.find(a);
    return it == pending_nonces_.end() ? 0 : it->second;
}

// ═════════════════════════════════════════════════════════════════════════════
// Hamiltonian Anti-MEV Shield
// ═════════════════════════════════════════════════════════════════════════════

namespace {

// Fee/amount of a tx in the local numeric domain.
inline uint64_t mev_amount(const Transaction& tx) noexcept {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | tx.amount[i];
    return v;
}
inline uint32_t mev_fee(const Transaction& tx) noexcept {
    uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | tx.fee[i];
    return v;
}
inline uint32_t mev_nonce(const Transaction& tx) noexcept {
    uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | tx.nonce[i];
    return v;
}

// 64-bit Galois-style mix (xorshift-multiply; division-free).
inline uint64_t galois_mix64(uint64_t x) noexcept {
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL; x ^= x >> 33;
    return x;
}

} // namespace

double mev_pair_energy(const Transaction& a, const Transaction& b) noexcept {
    // Receiver collision: the dominant sandwich coupling term.
    const bool receiver_collision =
        std::memcmp(a.receiver_nfa, b.receiver_nfa, 42) == 0;
    const bool sender_link =
        std::memcmp(a.sender_nfa, b.sender_nfa, 42) == 0;

    if (!receiver_collision && !sender_link) return 0.0;

    // Fee jump anomaly: |log-fee ratio| amplifies sandwich energy.
    const double fa = static_cast<double>(mev_fee(a)) + 1.0;
    const double fb = static_cast<double>(mev_fee(b)) + 1.0;
    const double fee_ratio = std::max(fa, fb) / std::min(fa, fb);
    const double fee_jump = std::log2(fee_ratio); // 0 for equal fees

    // Amount imbalance amplifies front-run profit potential.
    const double amt_a = static_cast<double>(mev_amount(a));
    const double amt_b = static_cast<double>(mev_amount(b));
    const double imbalance =
        std::fabs(amt_a - amt_b) / (std::max(amt_a, amt_b) + 1.0);

    double energy = fee_jump * (receiver_collision ? 3.0 : 1.0) + imbalance;
    if (fee_jump >= 3.0) energy += 5.0; // classic high-fee attacker signature
    return energy;
}

MevAuditReport Mempool::audit_and_neutralize_mev(std::span<Transaction> candidate_txs,
                                                 uint64_t prev_block_crc) {
    MevAuditReport report;
    const size_t n = candidate_txs.size();
    if (n == 0) return report;

    // ── 1. Interaction graph: union-find over colliding pairs ───────────────
    std::vector<size_t> parent(n);
    for (size_t i = 0; i < n; ++i) parent[i] = i;
    std::function<size_t(size_t)> find = [&](size_t x) -> size_t {
        while (parent[x] != x) x = parent[x] = parent[parent[x]];
        return x;
    };

    std::vector<std::vector<size_t>> edges(n);
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            const double e = mev_pair_energy(candidate_txs[i], candidate_txs[j]);
            if (e > 0.0) {
                edges[i].push_back(j);
                edges[j].push_back(i);
                // Fee-jump pairs are MEV suspect edges: union them.
                if (e >= 5.0) {
                    parent[find(i)] = find(j);
                }
            }
        }
    }

    // ── 2. Hamiltonian energy of the raw ordering ───────────────────────────
    // H = sum over adjacent pairs of the bundle (ordering-dependent term) +
    // half the total pairwise interaction energy (field term).
    auto hamiltonian_of_order = [&](const std::vector<size_t>& order) {
        double h = 0.0;
        for (size_t k = 0; k + 1 < order.size(); ++k) {
            h += mev_pair_energy(candidate_txs[order[k]], candidate_txs[order[k + 1]]);
        }
        // Field term: half of all pairwise energy (order-invariant part).
        double field = 0.0;
        for (size_t i = 0; i < n; ++i)
            for (const size_t j : edges[i]) field += mev_pair_energy(candidate_txs[i], candidate_txs[j]);
        return h + 0.5 * field;
    };

    std::vector<size_t> order_before(n);
    for (size_t i = 0; i < n; ++i) order_before[i] = i;
    report.order_before = order_before;
    report.initial_hamiltonian_energy = hamiltonian_of_order(order_before);

    // ── 3. Detect sandwich vectors: high-fee -> low-fee -> high-fee chains
    //    around the same receiver within one cluster. ────────────────────────
    std::unordered_map<size_t, std::vector<size_t>> clusters;
    for (size_t i = 0; i < n; ++i) clusters[find(i)].push_back(i);

    std::vector<bool> is_sandwich(n, false);
    for (auto& [root, members] : clusters) {
        if (members.size() < 3) continue;
        // Fee statistics of the cluster.
        std::vector<uint32_t> fees;
        for (const size_t i : members) fees.push_back(mev_fee(candidate_txs[i]));
        const double max_fee = *std::max_element(fees.begin(), fees.end());
        const double min_fee = *std::min_element(fees.begin(), fees.end());
        if (max_fee >= 4.0 * (min_fee + 1.0)) {
            // Fee spread consistent with sandwich: mark all members.
            for (const size_t i : members) is_sandwich[i] = true;
            report.sandwich_vectors_detected++;
        }
    }

    // ── 4. Neutralize: Canonical Galois Ordering per cluster. ────────────────
    // Key = CRC32C(prev_block_crc, nonce_and_tag) ^ galois_mix(tx bytes).
    // Fully deterministic: same inputs -> same canonical order on every node.
    if (report.sandwich_vectors_detected > 0 ||
        report.initial_hamiltonian_energy > 100.0 /* H_critical */) {
        report.neutralized = true;

        for (auto& [root, members] : clusters) {
            if (members.size() < 2) continue;
            std::vector<std::pair<uint64_t, size_t>> keyed;
            keyed.reserve(members.size());
            for (const size_t i : members) {
                const Transaction& tx = candidate_txs[i];
                const uint64_t nonce_and_tag =
                    (static_cast<uint64_t>(mev_nonce(tx)) << 32) ^
                    galois_mix64(mev_amount(tx));
                const uint32_t crc = vx::crypto::crc32c_hw(
                    reinterpret_cast<const uint8_t*>(tx.sender_nfa), 112);
                const uint64_t key =
                    (static_cast<uint64_t>(crc) ^ galois_mix64(prev_block_crc ^ nonce_and_tag));
                keyed.emplace_back(key, i);
            }
            std::sort(keyed.begin(), keyed.end(),
                      [](const auto& a, const auto& b) { return a.first < b.first; });
            std::vector<size_t> canonical;
            canonical.reserve(members.size());
            for (const auto& [key, i] : keyed) canonical.push_back(i);
            report.cluster_energies.push_back(hamiltonian_of_order(canonical));

            // Splice the canonical cluster order back into the bundle order.
            // Positions of cluster members (ascending original position).
            std::vector<size_t> positions;
            for (const size_t i : canonical) {
                for (size_t p = 0; p < n; ++p)
                    if (order_before[p] == i) { positions.push_back(p); break; }
            }
            std::sort(positions.begin(), positions.end());
            size_t k = 0;
            for (const size_t i : canonical) {
                order_before[positions[k++]] = i;
            }
        }

        // Materialize the canonical permutation into the span.
        std::vector<Transaction> out;
        out.reserve(n);
        for (const size_t i : order_before) out.push_back(candidate_txs[i]);
        std::copy(out.begin(), out.end(), candidate_txs.begin());

        report.order_after = order_before;
        report.post_shield_hamiltonian_energy = hamiltonian_of_order(order_before);
    } else {
        report.order_after = order_before;
        report.post_shield_hamiltonian_energy = report.initial_hamiltonian_energy;
        report.cluster_energies.push_back(report.initial_hamiltonian_energy);
    }

    return report;
}

} // namespace vx::state