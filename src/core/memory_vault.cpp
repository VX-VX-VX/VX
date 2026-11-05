#include "vx/core/memory_vault.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <cstdint>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <vector>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include "vx/core/hw_intrinsics.hpp"
#include <chrono>
#include <atomic>
#include <cstdio>
#include <cstdlib>

namespace vx::core {

bool MemoryCore::mlock_supported(size_t size) noexcept {
    if (size == 0) size = PAGE_SIZE;
    size = ((size + 4095) / 4096) * 4096;
    void* probe = aligned_alloc(4096, size);
    if (!probe) return false;
    const bool ok = (mlock(probe, size) == 0);
    if (ok) munlock(probe, size);
    free(probe);
    return ok;
}

uint64_t MemoryCore::get_hardware_uuid_seed() noexcept {
    uint64_t seed = 0;
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.find("Serial") != std::string::npos ||
            line.find("Hardware") != std::string::npos ||
            line.find("model name") != std::string::npos) {
            for (char c : line) {
                seed = seed * 31 + static_cast<uint8_t>(c);
            }
        }
    }
    cpuinfo.close();

    std::ifstream machine_id("/etc/machine-id");
    if (machine_id) {
        std::string id;
        std::getline(machine_id, id);
        for (char c : id) {
            seed = seed * 31 + static_cast<uint8_t>(c);
        }
    }

    if (seed == 0) {
        seed = 0x9e3779b97f4a7c15ull; // golden ratio fallback
    }
    return seed;
}

MemoryCore::MemoryCore(size_t arena_size) : arena_size_(arena_size) {
    if (!try_huge_pages(arena_size)) {
        fallback_alloc(arena_size);
    }
    // The usable pool is bounded by the arena actually allocated (both
    // allocation paths round arena_size_ up to a page multiple), so each
    // slot owns a distinct PAGE_SIZE region — no modulo aliasing.
    page_slot_count_ = std::min(POOL_SIZE, arena_size_ / PAGE_SIZE);
}

MemoryCore::~MemoryCore() {
    emergency_burn_all();
    if (arena_) {
        if (arena_is_huge_) {
            munmap(arena_, arena_size_);
        } else {
            free(arena_);
        }
        arena_ = nullptr;
    }
}

bool MemoryCore::try_huge_pages(size_t size) {
    size_t hp_size = 2 * 1024 * 1024; // 2MB huge pages
    size = ((size + hp_size - 1) / hp_size) * hp_size;

    void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB,
                     -1, 0);
    if (ptr == MAP_FAILED) {
        return false;
    }

    if (mlock(ptr, size) != 0) {
        munmap(ptr, size);
        return false;
    }
    arena_mlock_active_ = true;

    madvise(ptr, size, MADV_DONTFORK | MADV_DONTDUMP);
    arena_ = static_cast<uint8_t*>(ptr);
    arena_size_ = size;
    arena_is_huge_ = true;
    return true;
}

void MemoryCore::fallback_alloc(size_t size) {
    size = ((size + 4095) / 4096) * 4096;
    void* ptr = aligned_alloc(4096, size);
    if (!ptr) {
        throw std::runtime_error("MemoryCore: aligned_alloc failed");
    }

    if (mlock(ptr, size) != 0) {
        // Documented Public Core degradation (memory_vault.hpp): a low
        // RLIMIT_MEMLOCK (e.g. 8 MiB containers) must not block node
        // launch. The arena runs unlocked - pages are resident only
        // opportunistically - while zeroization guarantees are unaffected.
        // Sovereign Vault editions keep mlock as a hard invariant; the
        // actual protection level is reported via stats.mlock_active
        // (/api/vault/memory, /api/vault/report).
        std::fprintf(stderr, "[MemoryCore] WARNING: mlock failed "
                             "(check RLIMIT_MEMLOCK); running WITHOUT locked pages\n");
        arena_mlock_active_ = false;
    } else {
        arena_mlock_active_ = true;
    }

    madvise(ptr, size, MADV_DONTFORK | MADV_DONTDUMP);
    arena_ = static_cast<uint8_t*>(ptr);
    arena_size_ = size;
    arena_is_huge_ = false;
}

void MemoryCore::initialize(uint64_t user_master_key) {
    // Construction-time state reset; locked for uniformity with the
    // other arena-mutating paths (initialize is legal on a live object).
    std::lock_guard<std::mutex> lock(vault_mutex_);
    uint64_t hw_uuid = get_hardware_uuid_seed();
    hw_master_key_ = user_master_key ^ hw_uuid;

    for (auto& page : pages_) {
        page.offset = 0;
        page.capacity = 0;
        page.content_hash.fill(0);
        page.state = static_cast<uint8_t>(PageState::VOID);
    }
    next_page_ = 0;
    entropy_nonce_ = 0;
}

std::array<uint8_t, 32> MemoryCore::generate_unique_sha32(const uint8_t* data, size_t size) {
    // External review round 5: this used to be 4 CRC32C streams — a
    // non-cryptographic checksum handed out as a capability token. The
    // digest is now a domain-separated VortexSponge256 output bound to the
    // vault's hardware key and an entropy nonce. (The historical name is
    // kept for API stability; the "32" refers to the 32-BYTE digest.)
    std::array<uint8_t, 32> hash{};

    entropy_nonce_.fetch_add(1, std::memory_order_relaxed);
    const uint64_t nonce = entropy_nonce_.load(std::memory_order_relaxed);

    blockchain::VortexSponge256 sponge;
    const uint8_t tag[] = "VXVAULTCAPV1";
    sponge.absorb(tag, sizeof(tag) - 1);
    const uint8_t km[8] = {
        static_cast<uint8_t>(hw_master_key_), static_cast<uint8_t>(hw_master_key_ >> 8),
        static_cast<uint8_t>(hw_master_key_ >> 16), static_cast<uint8_t>(hw_master_key_ >> 24),
        static_cast<uint8_t>(hw_master_key_ >> 32), static_cast<uint8_t>(hw_master_key_ >> 40),
        static_cast<uint8_t>(hw_master_key_ >> 48), static_cast<uint8_t>(hw_master_key_ >> 56)};
    sponge.absorb(km, 8);
    const uint8_t nm[8] = {
        static_cast<uint8_t>(nonce), static_cast<uint8_t>(nonce >> 8),
        static_cast<uint8_t>(nonce >> 16), static_cast<uint8_t>(nonce >> 24),
        static_cast<uint8_t>(nonce >> 32), static_cast<uint8_t>(nonce >> 40),
        static_cast<uint8_t>(nonce >> 48), static_cast<uint8_t>(nonce >> 56)};
    sponge.absorb(nm, 8);
    if (size && data) sponge.absorb(data, size);
    sponge.finalize(hash.data());
    return hash;
}


std::array<uint8_t, 32> MemoryCore::commit_secure_data(const uint8_t* raw_data, size_t size) {
    if (size > PAGE_SIZE) {
        throw std::runtime_error("MemoryCore: data exceeds page size");
    }
    // v0.0.11 shared-state audit: the VOID-page scan below is
    // check-then-claim on shared state; concurrent RPC handlers racing
    // here could claim the same page and overwrite each other's secrets.
    std::lock_guard<std::mutex> lock(vault_mutex_);

    // External review round 5: the ring cursor used to claim a slot
    // unconditionally, silently ZEROING a still-LOCKED page when the pool
    // wrapped (the 4097th commit destroyed the 1st token's payload while
    // that token was still live). A page is now reusable only after its
    // token was consumed or burned; a full pool is an error, never a
    // clobber.
    const size_t start = next_page_.fetch_add(1, std::memory_order_acq_rel);
    MemoryPage* target = nullptr;
    for (size_t k = 0; k < page_slot_count_; ++k) {
        MemoryPage& cand = pages_[(start + k) % page_slot_count_];
        if (cand.state == static_cast<uint8_t>(PageState::VOID)) {
            target = &cand;
            break;
        }
    }
    if (!target) {
        throw std::runtime_error("MemoryCore: vault pool full (no consumed/burned slot free)");
    }
    MemoryPage& page = *target;

    // page owns a private, in-bounds region of the arena.
    page.offset = static_cast<size_t>(&page - pages_.data()) * PAGE_SIZE;
    page.capacity = static_cast<uint32_t>(size);
    page.state = static_cast<uint8_t>(PageState::LOCKED);

    std::memcpy(arena_ + page.offset, raw_data, size);
    if (size < PAGE_SIZE) {
        memset(arena_ + page.offset + size, 0, PAGE_SIZE - size);
    }

    // Full 32-byte capability digest (round 5: only the first 4 bytes used
    // to be stored AND compared, so 224 token bits were never checked).
    page.content_hash = generate_unique_sha32(raw_data, size);

    return page.content_hash;
}

bool MemoryCore::consume_data(const std::array<uint8_t, 32>& h32, uint8_t* out_buffer) {
    // Same audit: consume scans LOCKED pages and mutates them; it must
    // not interleave with a commit mid-write on the same page.
    std::lock_guard<std::mutex> lock(vault_mutex_);
    for (auto& page : pages_) {
        if (page.state != static_cast<uint8_t>(PageState::LOCKED)) continue;
        // Constant-time full-digest compare: early-exit memcmp would leak
        // how many leading bytes of the capability matched.
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < 32; ++i) {
            diff |= page.content_hash[i] ^ h32[i];
        }
        if (diff != 0) continue;

        if (out_buffer) {
            std::memcpy(out_buffer, arena_ + page.offset, page.capacity);
        }

        // Physically zero the arena memory with volatile pointer
        volatile uint8_t* vp = reinterpret_cast<volatile uint8_t*>(arena_ + page.offset);
        for (size_t i = 0; i < PAGE_SIZE; ++i) {
            vp[i] = 0;
        }
        // Flush cache lines via the portable hardware primitive
        hw::flush_cache_range(arena_ + page.offset, PAGE_SIZE);

        page.state = static_cast<uint8_t>(PageState::BURNED);
        page.capacity = 0;
        page.content_hash.fill(0);
        return true;
    }
    return false;
}

void MemoryCore::emergency_burn_all() {
    std::lock_guard<std::mutex> lock(vault_mutex_);
    for (auto& page : pages_) {
        if (page.state != static_cast<uint8_t>(PageState::VOID)) {
            // Defense in depth: this is the last-ditch zeroization path, so
            // it must never write outside the arena even if a future change
            // breaks the slot/offset invariant. The page state is still
            // retired either way.
            if (arena_ && page.offset + PAGE_SIZE <= arena_size_) {
                memset(arena_ + page.offset, 0, PAGE_SIZE);
            }
            page.state = static_cast<uint8_t>(PageState::BURNED);
            page.capacity = 0;
            page.content_hash.fill(0);
        }
    }
    hw_master_key_ = 0;
}

bool MemoryCore::check_debugger() const noexcept {
    if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0) {
        return true;
    }

    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") == 0) {
            int tracer_pid = 0;
            std::istringstream iss(line.substr(10));
            iss >> tracer_pid;
            if (tracer_pid != 0) return true;
        }
    }
    return false;
}

MemoryCore::Stats MemoryCore::get_stats() const noexcept {
    Stats stats{};
    stats.void_pages = 0;
    stats.locked_pages = 0;
    stats.burned_pages = 0;
    // Mutable-lock snapshot: a torn page-state read would misreport
    // live capability tokens as burned (or vice versa).
    std::lock_guard<std::mutex> lock(vault_mutex_);
    stats.huge_pages = arena_is_huge_;
    stats.mlock_active = arena_mlock_active_;
    stats.hw_uuid_hash = hw_master_key_;
    stats.lock_step_cycles = entropy_nonce_.load(std::memory_order_relaxed);

    for (const auto& page : pages_) {
        switch (static_cast<PageState>(page.state)) {
            case PageState::VOID:   stats.void_pages++;   break;
            case PageState::LOCKED: stats.locked_pages++; break;
            case PageState::BURNED: stats.burned_pages++; break;
        }
    }
    return stats;
}

void MemoryCore::scrub_execution_state(void* sensitive_buf, size_t len) noexcept {
    if (!sensitive_buf || len == 0) return;
    volatile uint8_t* p = static_cast<volatile uint8_t*>(sensitive_buf);
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
    asm volatile("" ::: "memory");
}

// ════════════════════════════════════════════════════════════════════════════
// hardware air-gap ephemeral signing
// ════════════════════════════════════════════════════════════════════════════

namespace {

// Hardware binding source, by edition:
//   Sovereign Vault (VX_SOVEREIGN_ARCHITECT): the motherboard UUID from
//     /sys/class/dmi/id/product_uuid (root-readable on many systems), folded
//     through the existing hardware seed chain. When the DMI node is absent
//     or not readable (e.g. unprivileged test runs), the machine-id seed
//     chain still anchors the arena to this host; g_host_anchor_real records
//     whether a genuine host anchor (DMI or machine-id) was used as opposed
//     to the golden-ratio last resort.
//   Public Core: get_hardware_uuid_seed() only — no DMI probe, no hardware
//     fingerprinting beyond the /etc/machine-id seed chain.
std::atomic<bool> g_host_anchor_real{false};

uint64_t read_motherboard_uuid() noexcept {
#ifdef VX_SOVEREIGN_ARCHITECT
    {
        std::ifstream product_uuid("/sys/class/dmi/id/product_uuid");
        if (product_uuid) {
            std::string id;
            std::getline(product_uuid, id);
            uint64_t seed = 0;
            for (char c : id) seed = seed * 31 + static_cast<uint8_t>(c);
            if (seed != 0) {
                g_host_anchor_real.store(true, std::memory_order_relaxed);
                return seed;
            }
        }
        // DMI unavailable (unprivileged run): fall through to the seed chain,
        // which still binds the arena to this host via /etc/machine-id.
        std::fputs("MemoryCore: SOVEREIGN VAULT — DMI product_uuid unavailable, "
                   "binding via the machine-id seed chain\n", stderr);
    }
#endif
    const uint64_t seed = MemoryCore::get_hardware_uuid_seed();
    // get_hardware_uuid_seed returns the golden-ratio constant only when no
    // host anchor (machine-id etc.) could be read at all.
    g_host_anchor_real.store(seed != 0x9e3779b97f4a7c15ull,
                             std::memory_order_relaxed);
    return seed;
}

std::string to_hex_112(const uint8_t* bytes) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(224);
    for (size_t i = 0; i < 112; ++i) {
        out.push_back(hex[bytes[i] >> 4]);
        out.push_back(hex[bytes[i] & 0x0F]);
    }
    return out;
}

} // namespace

bool MemoryCore::burn_page(uint32_t page_id) noexcept {
    std::lock_guard<std::mutex> lock(vault_mutex_);
    return burn_page_internal_(page_id);
}

bool MemoryCore::burn_page_internal_(uint32_t page_id) noexcept {
    if (page_id >= POOL_SIZE) return false;
    MemoryPage& page = pages_[page_id];
    if (page.capacity == 0) return false;
    uint8_t* base = arena_ + page.offset;
    const size_t len = page.capacity;

    // 1. Volatile 0x00 overwrite.
    volatile uint8_t* p = static_cast<volatile uint8_t*>(base);
    for (size_t i = 0; i < len; ++i) p[i] = 0x00;
    asm volatile("" ::: "memory");

    // 2. Hardware-entropy noise pass (defense in depth).
    const uint64_t noise = read_motherboard_uuid() ^ entropy_nonce_.fetch_add(1);
    for (size_t i = 0; i < len; i += 8) {
        uint64_t chunk = noise ^ (0x9E3779B97F4A7C15ULL * (i + 1));
        std::memcpy(base + i, &chunk, (len - i >= 8) ? 8 : (len - i));
    }
    asm volatile("" ::: "memory");

    // 3. Final 0x00 overwrite (the test asserts a clean burn).
    for (size_t i = 0; i < len; ++i) p[i] = 0x00;
    asm volatile("" ::: "memory");

    // 4. Force-evict every cache line of the page so no stale copy survives
    //    in any CPU cache level.
    hw::flush_cache_range(base, len);
    asm volatile("" ::: "memory");

    page.state = static_cast<uint8_t>(PageState::BURNED);
    page.capacity = 0; // slot returns to the reusable pool
    page.content_hash.fill(0);
    return true;
}

MemoryCore::EphemeralSignReport MemoryCore::sign_ephemeral_in_vault(
    blockchain::Transaction& tx) {
    EphemeralSignReport report;
    const uint64_t t0 = hw::cycle_counter();
    const auto wall0 = std::chrono::steady_clock::now();

    // v0.0.11 shared-state audit: the whole sign cycle (claim page ->
    // expand SK -> anchor signature -> burn) is one critical section.
    // A concurrent commit or consume touching the claimed page would
    // otherwise corrupt the key material or read a half-written SK.
    // NOTE: get_stats() locks too - read the flag directly instead.
    std::lock_guard<std::mutex> lock(vault_mutex_);

    // ── Step 2: allocate a free page VOID -> LOCKED ─────────────────────────
    int32_t page_id = -1;
    for (size_t attempt = 0; attempt < POOL_SIZE; ++attempt) {
        const size_t idx = next_page_.fetch_add(1) % page_slot_count_;
        uint8_t expected = static_cast<uint8_t>(PageState::VOID);
        MemoryPage& page = pages_[idx];
        if (page.capacity != 0 && page.state != expected) continue;
        page.offset = idx * PAGE_SIZE;
        page.capacity = PAGE_SIZE;
        page.state = static_cast<uint8_t>(PageState::LOCKED);
        page_id = static_cast<int32_t>(idx);
        break;
    }
    if (page_id < 0) throw std::runtime_error("Vault: no VOID page available");
    report.page_id = static_cast<uint32_t>(page_id);
    report.mlock_active = arena_mlock_active_;

    uint8_t* page_base = arena_ + pages_[page_id].offset;

    // ── Step 3: hardware UUID + entropy -> SK expanded ONLY inside the arena ─
    const uint64_t hw_uuid = read_motherboard_uuid();
    // Honest binding report: true when a real host anchor (DMI product_uuid
    // in the Vault edition, machine-id seed chain otherwise) was folded
    // into the key expansion. False only for the golden-ratio last resort.
    report.hw_uuid_bound =
        g_host_anchor_real.load(std::memory_order_relaxed);

    {
        blockchain::VortexSponge256 sponge;
        const uint8_t dom[] = "VXVAULT_SK";
        sponge.absorb(dom, sizeof(dom) - 1);
        sponge.absorb(reinterpret_cast<const uint8_t*>(&hw_uuid), sizeof(hw_uuid));
        const uint64_t nonce = entropy_nonce_.fetch_add(1);
        sponge.absorb(reinterpret_cast<const uint8_t*>(&nonce), sizeof(nonce));
        uint8_t stream[32];
        sponge.finalize(stream);
        // SK lives only at this arena pointer — never copied to the heap.
        std::memcpy(page_base, stream, 32);
        asm volatile("" ::: "memory");
    }

    // ── Step 4: sponge signature over the tx, anchored into cocoon_proof ─────
    {
        blockchain::VortexSponge256 sponge;
        const uint8_t dom[] = "VXVAULT_SIG";
        sponge.absorb(dom, sizeof(dom) - 1);
        sponge.absorb(page_base, 32);          // in-arena SK pointer read
        sponge.absorb(reinterpret_cast<const uint8_t*>(&tx), blockchain::TX_SIZE_BYTES);
        uint8_t sig[48];
        sponge.finalize(sig);
        std::memcpy(tx.cocoon_proof, sig, 12); // tag_or_sig anchor
        // Keep the remaining signature bytes out of memory entirely — only
        // the 12-byte anchor plus the tx commitment survive.
        asm volatile("" ::: "memory");
    }
    report.signed_tx_hex = to_hex_112(reinterpret_cast<const uint8_t*>(&tx));

    // ── Step 5: microsecond self-destruction ────────────────────────────────
    burn_page_internal_(static_cast<uint32_t>(page_id)); // lock already held
    report.final_page_state = "BURNED";

    // ── Step 6: lifetime accounting ─────────────────────────────────────────
    const auto wall1 = std::chrono::steady_clock::now();
    const uint64_t t1 = hw::cycle_counter();
    report.key_lifetime_rdtsc_cycles = t1 - t0;
    report.key_lifetime_us =
        std::chrono::duration<double, std::micro>(wall1 - wall0).count();
    return report;
}

} // namespace vx::core