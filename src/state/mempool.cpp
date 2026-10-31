#include "vx/state/mempool.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/simd_accel.hpp"
#include "vx/math/tdi_filter.hpp"
#include <algorithm>
#include <cmath>
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


bool Mempool::validate_pending(const Transaction& tx, const U128& sender_balance, uint32_t sender_nonce) const noexcept {
    Address sender = tx_address(tx.sender_nfa);
    uint64_t amount = tx_amount_local(tx);
    uint32_t fee = tx_fee_local(tx);
    uint32_t nonce = tx_nonce_local(tx);

    // Check nonce
    std::lock_guard<std::mutex> lock(pending_mutex_);
    auto nonce_it = pending_nonces_.find(sender);
    uint32_t expected_nonce = (nonce_it == pending_nonces_.end()) ? sender_nonce : nonce_it->second;

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

std::optional<size_t> Mempool::find_slot() noexcept {
    size_t current = count_.load(std::memory_order_relaxed);
    if (current >= MEMPOOL_MAX_TXS) {
        return std::nullopt;
    }

    // Try to claim a slot atomically
    while (true) {
        size_t expected = current;
        if (count_.compare_exchange_weak(expected, current + 1, std::memory_order_acq_rel)) {
            return current;
        }
        current = expected;
        if (current >= MEMPOOL_MAX_TXS) {
            return std::nullopt;
        }
    }
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

    // 3. Validate against pending state (nonce + balance)
    if (!validate_pending(tx, sender_balance, sender_nonce)) {
        result.error = "nonce mismatch or insufficient balance (including pending)";
        return result;
    }

    // 4. Find a slot
    auto slot = find_slot();
    if (!slot) {
        result.error = "mempool full (16,384 tx limit)";
        return result;
    }

    // 5. Compute priority
    double priority = compute_priority(tx);
    uint32_t fee = tx_fee_local(tx);
    uint32_t nonce = tx_nonce_local(tx);
    Address sender = tx_address(tx.sender_nfa);

    // 6. Insert entry (with version for optimistic concurrency)
    Entry& entry = entries_[*slot];
    entry.tx = tx;
    entry.fee = U128(fee);
    entry.amount = U128(amount);
    entry.priority = priority;
    entry.sender_nonce = nonce;
    entry.valid = true;

    // 7. Update pending state
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_outgoing_[sender] = pending_outgoing_[sender] + U128(amount + fee);
        pending_nonces_[sender] = nonce + 1;
    }

    version_.fetch_add(1, std::memory_order_release);

    result.ok = true;
    result.position = *slot;
    result.projected_height = 0; // Will be set by caller
    return result;
}

MempoolStats Mempool::stats() const noexcept {
    MempoolStats s;
    size_t cnt = count_.load(std::memory_order_relaxed);
    s.count = cnt;
    s.byte_occupancy = cnt * 112;
    s.utilization_pct = (static_cast<double>(cnt) / 580.0) * 100.0; // 580 tx = full 64KB frame

    // Sum up fees and amounts (read-only, no lock needed for approximate stats)
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
    size_t cnt = count_.load(std::memory_order_acquire);
    if (cnt == 0 || max_count == 0) return {};

    // Collect valid entries with their indices
    struct Candidate {
        size_t index;
        double priority;
        uint32_t sender_nonce;
    };
    std::vector<Candidate> candidates;
    candidates.reserve(cnt);

    for (size_t i = 0; i < cnt; ++i) {
        if (entries_[i].valid) {
            candidates.push_back({i, entries_[i].priority, entries_[i].sender_nonce});
        }
    }

    // Sort by priority (highest first), then by sender_nonce for fairness
    std::sort(candidates.begin(), candidates.end(),
        [](const Candidate& a, const Candidate& b) {
            if (std::abs(a.priority - b.priority) > 1e-9) {
                return a.priority > b.priority; // Higher priority first
            }
            return a.sender_nonce < b.sender_nonce; // Lower nonce first (FIFO per sender)
        });

    // Take up to max_count
    size_t take = std::min(max_count, candidates.size());
    std::vector<Transaction> result;
    result.reserve(take);

    for (size_t i = 0; i < take; ++i) {
        result.push_back(entries_[candidates[i].index].tx);
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

    // Remove sealed entries and update pending state
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        for (size_t i = 0; i < count_.load(std::memory_order_relaxed); ++i) {
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
                            pending_it->second = U128{0};
                        }
                        if (pending_it->second.is_zero()) {
                            pending_outgoing_.erase(pending_it);
                        }
                    }

                    // Reset pending nonce to the next expected value
                    pending_nonces_[sender] = entries_[i].sender_nonce + 1;

                    // Invalidate entry
                    entries_[i].valid = false;
                }
            }
        }
    }

    // Compact the array (move valid entries to front)
    size_t write_idx = 0;
    size_t read_cnt = count_.load(std::memory_order_relaxed);
    for (size_t i = 0; i < read_cnt; ++i) {
        if (entries_[i].valid) {
            if (write_idx != i) {
                entries_[write_idx] = entries_[i];
            }
            ++write_idx;
        }
    }

    // Update count
    size_t old_count = count_.exchange(write_idx, std::memory_order_acq_rel);
    (void)old_count;
    version_.fetch_add(1, std::memory_order_release);
}

void Mempool::clear() noexcept {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    pending_outgoing_.clear();
    pending_nonces_.clear();

    for (size_t i = 0; i < count_.load(std::memory_order_relaxed); ++i) {
        entries_[i].valid = false;
    }
    count_.store(0, std::memory_order_release);
    version_.fetch_add(1, std::memory_order_release);
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