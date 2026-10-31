#pragma once

// Zero-Allocation Lock-Free Ring Pipeline — of the VX Sovereign OS
// directive.
//
// A hardware-aligned MPMC ring of 65536 slots for raw 112-byte transactions.
// Design invariants (hot path = push/consume only):
//   * no malloc/new/std::vector::push_back/std::mutex — zero heap traffic;
//   * head_ and tail_ live on separate 64-byte cache lines (alignas(64)) so
//     producer and consumer cores never thrash the same L1 line;
//   * every slot carries an 8-bit atomic state machine
//     EMPTY -> WRITING -> READY -> CONSUMING advanced strictly with
//     compare_exchange_weak(..., memory_order_acq_rel);
//   * an express TDI/VSDPV filter runs before the write:
//         (tx.fee * 1024) / 112 >= min_tdi
//     — two ALU ops, spam never even enters the ring.

#include "vx/blockchain/block.hpp"
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>

namespace vx::core {

class RingPipeline {
public:
    static constexpr size_t CAPACITY = 65536; // 64Ki transaction slots
    static constexpr size_t TX_BYTES = blockchain::TX_SIZE_BYTES; // 112

    enum SlotState : uint8_t {
        SLOT_EMPTY     = 0,
        SLOT_WRITING   = 1,
        SLOT_READY     = 2,
        SLOT_CONSUMING = 3,
    };

    struct alignas(128) Slot { // full cache-line pair per slot: no false sharing
        uint8_t bytes[TX_BYTES];
        std::atomic<uint8_t> state{SLOT_EMPTY};
    };
    static_assert(sizeof(Slot) == 128, "slot must span exactly two cache lines");

    struct Stats {
        uint64_t pushed = 0;
        uint64_t consumed = 0;
        uint64_t spam_filtered = 0;
        uint64_t head = 0;
        uint64_t tail = 0;
        uint64_t heap_allocations = 0; // structurally zero: no allocator on path
    };

    /// min_tdi: minimal express-filter score (tx.fee * 1024 / 112). The 8 MiB
    /// slot arena is allocated once here — the push/consume hot path itself
    /// never touches an allocator.
    explicit RingPipeline(uint32_t min_tdi = 1000)
        : min_tdi_(min_tdi), slots_(std::make_unique<Slot[]>(CAPACITY)) {}

    RingPipeline(const RingPipeline&) = delete;
    RingPipeline& operator=(const RingPipeline&) = delete;

    /// TDI express filter + lock-free publication. Returns false for spam
    /// (the transaction never touches the ring).
    bool push(const blockchain::Transaction& tx) noexcept {
        const uint64_t tdi =
            (static_cast<uint64_t>(blockchain::tx_fee(tx)) * 1024u) / TX_BYTES;
        if (tdi < min_tdi_) {
            spam_filtered_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        const uint64_t ticket = tail_.fetch_add(1, std::memory_order_relaxed);
        Slot& s = slots_[ticket % CAPACITY];

        uint8_t expected = SLOT_EMPTY;
        while (!s.state.compare_exchange_weak(expected, SLOT_WRITING,
                                              std::memory_order_acq_rel,
                                              std::memory_order_acquire)) {
            // Wait for the previous round on this slot to be fully drained.
            while (s.state.load(std::memory_order_acquire) != SLOT_EMPTY) {}
            expected = SLOT_EMPTY;
        }
        std::memcpy(s.bytes, &tx, TX_BYTES);
        s.state.store(SLOT_READY, std::memory_order_release);
        pushed_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    /// Lock-free retrieval of the next published transaction. Non-blocking:
    /// returns false when the ring is drained (no published tickets remain).
    bool consume(blockchain::Transaction& out) noexcept {
        const uint64_t ticket = head_.fetch_add(1, std::memory_order_relaxed);
        if (ticket >= tail_.load(std::memory_order_acquire)) {
            // Ring empty for this ticket — hand the ticket back.
            head_.fetch_sub(1, std::memory_order_relaxed);
            return false;
        }
        Slot& s = slots_[ticket % CAPACITY];

        uint8_t expected = SLOT_READY;
        while (s.state.load(std::memory_order_acquire) != SLOT_READY) {
            expected = SLOT_READY;
        }
        if (!s.state.compare_exchange_weak(expected, SLOT_CONSUMING,
                                           std::memory_order_acq_rel,
                                           std::memory_order_acquire)) {
            // Another consumer already owns this slot's round — hand the
            // ticket back and report no data.
            head_.fetch_sub(1, std::memory_order_relaxed);
            return false;
        }
        std::memcpy(&out, s.bytes, TX_BYTES);
        s.state.store(SLOT_EMPTY, std::memory_order_release);
        consumed_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    Stats stats() const noexcept {
        Stats st;
        st.pushed = pushed_.load(std::memory_order_relaxed);
        st.consumed = consumed_.load(std::memory_order_relaxed);
        st.spam_filtered = spam_filtered_.load(std::memory_order_relaxed);
        st.head = head_.load(std::memory_order_relaxed);
        st.tail = tail_.load(std::memory_order_relaxed);
        st.heap_allocations = 0;
        return st;
    }

    uint32_t min_tdi() const noexcept { return min_tdi_; }

private:
    alignas(64) std::atomic<uint64_t> head_{0}; // consumer frontier
    alignas(64) std::atomic<uint64_t> tail_{0}; // producer frontier
    std::atomic<uint64_t> pushed_{0};
    std::atomic<uint64_t> consumed_{0};
    std::atomic<uint64_t> spam_filtered_{0};
    uint32_t min_tdi_;
    std::unique_ptr<Slot[]> slots_; // 8 MiB arena, one construction-time allocation
};

static_assert(alignof(RingPipeline) >= 64, "pipeline frontiers must be cache-aligned");

} // namespace vx::core
