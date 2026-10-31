#pragma once

#include "vx/blockchain/block.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/core/u128.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <optional>
#include <unordered_set>
#include <vector>

namespace vx::state {

using blockchain::Address;
using blockchain::Transaction;
using core::U128;

/// Maximum mempool capacity (16,384 transactions = ~1.8 MB)
inline constexpr size_t MEMPOOL_MAX_TXS = 16384;

/// Result of submitting a transaction to the mempool
struct SubmitResult {
    bool ok = false;
    std::string error;
    size_t position = 0;        // Position in mempool (0 = highest priority)
    uint64_t projected_height = 0;
};

/// Mempool statistics
struct MempoolStats {
    size_t count = 0;
    size_t byte_occupancy = 0;      // count * 112
    double utilization_pct = 0.0;   // percentage of 64KB frame capacity
    U128 total_pending_fees;
    U128 total_pending_amounts;
};

// ── Hamiltonian Anti-MEV Shield ───────────────────────────────────

/// Report of an MEV audit over a candidate transaction bundle.
struct MevAuditReport {
    double initial_hamiltonian_energy = 0.0;   // H of the raw bundle
    double post_shield_hamiltonian_energy = 0.0; // H after canonical reorder
    size_t sandwich_vectors_detected = 0;      // sandwich / front-run patterns
    std::vector<size_t> order_before;           // indices into the bundle
    std::vector<size_t> order_after;            // canonical Galois order
    std::vector<double> cluster_energies;       // per conflict-cluster H
    bool neutralized = false;                   // true when a reorder happened
};

/// Pairwise interaction energy contribution between two transactions
/// (receiver collision => front-run/sandwich coupling; fee anomaly boost).
double mev_pair_energy(const Transaction& a, const Transaction& b) noexcept;

/**
 * @brief Lock-free / Thread-Safe Mempool Engine
 *
 * Capacity: up to 16,384 pending 112-byte transactions in RAM.
 * Priority ordering: rank by TDI fee-entropy density (fee / entropy_cost)
 * while preserving per-sender nonce order.
 * Double-spend & balance guard: track pending_outgoing_balance and pending_nonce
 * so a user cannot queue transactions exceeding their available balance.
 */
class Mempool {
public:
    Mempool() = default;

    /// Submit a transaction to the mempool
    /// Validates signature, TDI, balance, and nonce
    SubmitResult submit(const Transaction& tx, const U128& sender_balance, uint32_t sender_nonce);

    /// Get next expected nonce for an address (from ledger + pending)
    uint32_t get_next_nonce(const Address& a) const noexcept;

    /// Get current mempool statistics
    MempoolStats stats() const noexcept;

    /// Get up to N highest-priority transactions for block sealing
    /// Returns them in priority order (highest first)
    std::vector<Transaction> pull_for_sealing(size_t max_count) noexcept;

    /// Remove specific transactions from mempool (after they're sealed in a block)
    void remove_sealed(const std::vector<Transaction>& sealed_txs) noexcept;

    /// Clear entire mempool
    void clear() noexcept;

  // ── Hamiltonian Anti-MEV Shield ────────────────────────────────

    /// Build the interaction graph for a candidate bundle, detect
    /// sandwich/front-run vectors, compute the bundle's Hamiltonian energy,
    /// and — when a MEV pattern or super-critical energy is found — apply
    /// Canonical Galois Ordering (deterministic CRC32C-seeded sort) inside
    /// each conflict cluster, minimizing the final energy.
    MevAuditReport audit_and_neutralize_mev(std::span<Transaction> candidate_txs,
                                            uint64_t prev_block_crc);

    /// Check if empty
    bool empty() const noexcept { return count_.load(std::memory_order_relaxed) == 0; }

    /// Get current transaction count
    size_t count() const noexcept { return count_.load(std::memory_order_relaxed); }

    // Delete copy/move
    Mempool(const Mempool&) = delete;
    Mempool& operator=(const Mempool&) = delete;
    Mempool(Mempool&&) = delete;
    Mempool& operator=(Mempool&&) = delete;

private:
    // Internal entry with metadata for priority queue
    struct Entry {
        Transaction tx;
        U128 fee;
        U128 amount;
        double priority;        // fee / entropy_cost (higher = better)
        uint32_t sender_nonce;  // For nonce ordering per sender
        bool valid = false;
    };

    // Lock-free ring buffer for entries
    alignas(64) std::array<Entry, MEMPOOL_MAX_TXS> entries_;
    alignas(64) std::atomic<size_t> count_{0};
    alignas(64) std::atomic<uint64_t> version_{0};  // For optimistic locking

    // Per-sender pending state (protected by mutex for simplicity, can be lock-free later)
    mutable std::mutex pending_mutex_;
    std::unordered_map<Address, U128, AddressHash> pending_outgoing_;
    std::unordered_map<Address, uint32_t, AddressHash> pending_nonces_;

    // Compute TDI-based priority for a transaction
    double compute_priority(const Transaction& tx) const noexcept;

    // Find next available slot (lock-free)
    std::optional<size_t> find_slot() noexcept;

    // Validate transaction against pending state
    bool validate_pending(const Transaction& tx, const U128& sender_balance, uint32_t sender_nonce) const noexcept;
};

} // namespace vx::state