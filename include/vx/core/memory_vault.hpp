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

enum class PageState : uint8_t {
    VOID = 0,
    LOCKED = 1,
    BURNED = 2
};

struct alignas(16) MemoryPage {
    // Default member initializers are load-bearing: the page pool must be
    // fully VOID the moment the core is constructed. Relying on the caller
    // to run initialize() first left the pool holding stack garbage, and
    // emergency_burn_all() then zeroized bogus arena offsets (the crash
    // Clang/ASan exposed; GCC merely got lucky with zeroed stack memory).
    size_t offset = 0;
    uint32_t capacity = 0;
    uint32_t content_hash = 0;
    uint8_t state : 2 = 0; // PageState::VOID
    uint8_t reserved : 6 = 0;
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

    // Hardware master key (user_key ^ hw_uuid)
    uint64_t hw_master_key_ = 0;

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

    // Huge page support
    bool try_huge_pages(size_t size);
    void fallback_alloc(size_t size);
};

} // namespace vx::core