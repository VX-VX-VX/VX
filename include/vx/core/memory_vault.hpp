#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <array>
#include <string>
#include <optional>
#include <functional>

#include "vx/blockchain/block.hpp"

namespace vx::core {

/// Capability digest width (32 bytes, full VortexSponge256 output).
inline constexpr size_t VAULT_HASH_SIZE = 32;

enum class PageState : uint8_t {
    VOID = 0,
    LOCKED = 1,
    BURNED = 2,
    // Transient owner-held state (vault lock split, 2026-11-07): a thread
    // won the page's state CAS and is writing/reading/burning its contents.
    // Every plain (non-atomic) access to a page's offset/capacity/hash/data
    // happens either while holding CLAIMED or after acquiring CLAIMED from
    // LOCKED - the state field is the only synchronization edge.
    CLAIMED = 3
};

struct alignas(16) MemoryPage {
    // Default member initializers are load-bearing: the page pool must be
    // fully VOID the moment the core is constructed. Relying on the caller
    // to run initialize() first left the pool holding stack garbage, and
    // emergency_burn_all() then zeroized bogus arena offsets (the crash
    // Clang/ASan exposed; GCC merely got lucky with zeroed stack memory).
    size_t offset = 0;
    uint32_t capacity = 0;
    // Full 32-byte capability digest (external review round 5: the old
    // uint32_t field made the "256-bit" token effectively 32 bits — the
    // remaining 224 token bytes were never checked on consume).
    // ATOMIC BYTES (vault lock split): the digest is compared lock-free
    // while a page is LOCKED, and the emergency-burn sweep may zero it
    // concurrently after claiming the page - so both sides go through
    // atomic byte access. The digest is immutable while LOCKED (only the
    // CLAIMED committer writes it before publishing), so torn reads are
    // impossible in practice; atomics make the model race-free, the
    // compare itself stays constant-time byte-wise.
    std::array<std::atomic<uint8_t>, VAULT_HASH_SIZE> content_hash{};
    // Page-state word (vault lock split: plain 2-bit bitfield -> atomic).
    // Plain members (offset/capacity) are protected by this word's
    // release/acquire edges, not by a global lock.
    std::atomic<uint8_t> state{0}; // PageState::VOID
};

class MemoryCore {
public:
    static constexpr size_t DEFAULT_ARENA_SIZE = 16 * 1024 * 1024; // 16 MB dev
    static constexpr size_t PROD_ARENA_SIZE = 512 * 1024 * 1024;   // 512 MB prod
    static constexpr size_t PAGE_SIZE = 4096;
    static constexpr size_t POOL_SIZE = 16384;
    static constexpr size_t HASH_SIZE = 32;

    explicit MemoryCore(size_t arena_size = DEFAULT_ARENA_SIZE);
    ~MemoryCore();

    MemoryCore(const MemoryCore&) = delete;
    MemoryCore& operator=(const MemoryCore&) = delete;
    MemoryCore(MemoryCore&&) = delete;
    MemoryCore& operator=(MemoryCore&&) = delete;

    // Get hardware UUID seed for DNA binding
    static uint64_t get_hardware_uuid_seed() noexcept;

    // Capability probe: true iff the environment permits mlock of `size`
    // bytes (RLIMIT_MEMLOCK, container restrictions). Purely observational —
    // locks and immediately unlocks a scratch page range, no arena touched.
    // Tests use it to skip locked-arena coverage in restricted environments
    // (CI containers); the arena constructor itself stays strict.
    static bool mlock_supported(size_t size = DEFAULT_ARENA_SIZE) noexcept;

    // Initialize with user master key (XORed with hw_uuid)
    void initialize(uint64_t user_master_key);

    // Allocate a page, copy data, mark LOCKED, return 32-byte hash
    std::array<uint8_t, HASH_SIZE> commit_secure_data(const uint8_t* raw_data, size_t size);

    // Read data and immediately BURN the page (zero memory, mark BURNED)
    bool consume_data(const std::array<uint8_t, HASH_SIZE>& h32, uint8_t* out_buffer);

    // Emergency burn all pages
    void emergency_burn_all();

  // ── hardware air-gap ephemeral signing ──────────────────────
    struct EphemeralSignReport {
        std::string signed_tx_hex;            // 112B tx after signature anchoring
        uint32_t page_id = 0;
        std::string final_page_state;         // always "BURNED" on success
        uint64_t key_lifetime_rdtsc_cycles = 0;
        double key_lifetime_us = 0.0;
        bool hw_uuid_bound = false;
        bool mlock_active = false;
    };

    /// Sign a 112-byte transaction with a key that is expanded inside a
    /// locked vault page and destroyed microseconds later:
    ///   rdtsc t0 -> VOID->LOCKED page -> hw-UUID-bound SK expansion in the
    ///   arena (no heap copy) -> sponge signature anchored into
    ///   tx.cocoon_proof -> volatile zeroization + _mm_clflush of every cache
    ///   line -> PageState::BURNED -> rdtsc t1.
    EphemeralSignReport sign_ephemeral_in_vault(blockchain::Transaction& tx);

    /// Force-burn a single page: 0x00 overwrite + hardware-entropy noise +
    /// final 0x00, cache flush of every line, state -> BURNED.
    bool burn_page(uint32_t page_id) noexcept;

    // Check if debugger attached
    bool check_debugger() const noexcept;

    // Get live statistics
    struct Stats {
        size_t void_pages;
        size_t locked_pages;
        size_t burned_pages;
        bool huge_pages;
        bool mlock_active;
        uint64_t hw_uuid_hash;
        size_t lock_step_cycles;
    };
    Stats get_stats() const noexcept;

    // Scrub execution registers and cache
    static void scrub_execution_state(void* sensitive_buf, size_t len) noexcept;

private:
    // Generate unique SHA-32 hash using SSE4.2 CRC32
    std::array<uint8_t, HASH_SIZE> generate_unique_sha32(const uint8_t* data, size_t size);

    // Hardware master key (user_key ^ hw_uuid). Atomic: emergency_burn_all
    // zeroes it while concurrent commits may be deriving capability digests
    // from it (vault lock split - the global vault_mutex_ is gone).
    std::atomic<uint64_t> hw_master_key_{0};

    // Emergency-wipe latch (vault lock split): set by emergency_burn_all
    // BEFORE the sweep so no new page claims can start during the drain -
    // without it a sustained claim stream could keep the drain loop waiting
    // indefinitely (the mutex version got termination for free by queueing).
    // The latch STAYS SET: post-wipe the vault is retired (the pre-split
    // code could never reuse a burned page, so post-emergency commits were
    // a guaranteed pool-full error anyway). initialize() clears it.
    std::atomic<bool> emergency_wipe_{false};

    // Arena memory
    uint8_t* arena_ = nullptr;
    public:
    size_t arena_size_ = 0;
    bool arena_is_huge_ = false;

    // True when the arena pages are actually locked into RAM (mlock). In the
    // Sovereign Vault edition this is a hard invariant; in the public build
    // an mlock failure degrades gracefully with zeroization still guaranteed.
    bool arena_mlock_active_ = false;

    // Ring buffer for page allocation. page_slot_count_ is the number of
    // pool slots the arena can actually back (POOL_SIZE, but capped by
    // arena_size_ / PAGE_SIZE) — never allocate a page whose backing memory
    // would have to alias another page's.
    std::array<MemoryPage, POOL_SIZE> pages_;
    size_t page_slot_count_ = POOL_SIZE;
    std::atomic<size_t> next_page_{0};
    std::atomic<size_t> entropy_nonce_{0};

    // Page-state protocol (vault lock split, owner pattern 2026-11-05 II.1;
    // replaces the v0.0.11 global vault_mutex_): every page transition is a
    // CAS on pages_[i].state and pages are physically disjoint arena
    // regions, so the only globally-serialized step is the ~20 ns claim -
    // heavy key expansion / signing / zeroization / cache flushing run
    // lock-free on the claimed page and publish the final state with
    // memory_order_release. Page i's work never contends with page j's.
    // One behavioral note recorded honestly: a transient CLAIMED page makes
    // the pool look one slot smaller to concurrent committers (the mutex
    // version made them QUEUE instead); at 16384 slots vs the live RPC
    // thread count this never approaches the pool-full error.

    // Huge page support
    bool try_huge_pages(size_t size);
    void fallback_alloc(size_t size);

    // Burn variant called with the page's CLAIMED state already won (the
    // ephemeral-sign path burns its own claimed page; the public burn_page
    // claims first). Zeroize + noise + flush + BURNED release-store.
    bool burn_page_claimed_(uint32_t page_id) noexcept;
};

} // namespace vx::core