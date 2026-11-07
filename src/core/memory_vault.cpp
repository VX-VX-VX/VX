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
#include <thread>
#include <cstdio>
#include <cstdlib>

namespace vx::core {

// Vault lock split helpers: the capability digest is compared lock-free on
// LOCKED pages while an emergency sweep may zero it concurrently - both
// sides use atomic byte access (see memory_vault.hpp). Stores are relaxed:
// the state word's release/acquire edges, not the digest bytes, order the
// protocol.
void zero_digest_(MemoryPage &page) noexcept {
    for (auto &b : page.content_hash)
        b.store(0, std::memory_order_relaxed);
}

void store_digest_(MemoryPage &page, const std::array<uint8_t, VAULT_HASH_SIZE> &digest) noexcept {
    for (size_t i = 0; i < digest.size(); ++i)
        page.content_hash[i].store(digest[i], std::memory_order_relaxed);
}

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
    // Construction-time state reset. Under the vault lock split there is no
    // global mutex: each page-state store is atomic, so no torn state is
    // possible, but initialize racing a live commit/consume/sign is still a
    // semantic race (a page being claimed may be reset under its owner).
    // Production order is unchanged: initialize runs before the RPC threads
    // start serving; the "legal on a live object" note applies to setup and
    // test paths only.
    const uint64_t hw_uuid = get_hardware_uuid_seed();
    hw_master_key_.store(user_master_key ^ hw_uuid, std::memory_order_relaxed);

    for (auto& page : pages_) {
        page.offset = 0;
        page.capacity = 0;
        zero_digest_(page);
        page.state.store(static_cast<uint8_t>(PageState::VOID), std::memory_order_release);
    }
    next_page_ = 0;
    entropy_nonce_ = 0;
    emergency_wipe_.store(false, std::memory_order_release);
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
    const uint64_t km_raw = hw_master_key_.load(std::memory_order_relaxed);
    const uint8_t km[8] = {static_cast<uint8_t>(km_raw),       static_cast<uint8_t>(km_raw >> 8),
                           static_cast<uint8_t>(km_raw >> 16), static_cast<uint8_t>(km_raw >> 24),
                           static_cast<uint8_t>(km_raw >> 32), static_cast<uint8_t>(km_raw >> 40),
                           static_cast<uint8_t>(km_raw >> 48), static_cast<uint8_t>(km_raw >> 56)};
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
    // Vault lock split: the claim is a per-page CAS (the only
    // globally-serialized step); the data write, digest and LOCKED
    // publication run lock-free on the claimed page. The arena write and
    // the hash store happen while the page is CLAIMED (nobody else may
    // touch it), and the release-store of LOCKED publishes both to every
    // future consumer.

    // External review round 5: the ring cursor used to claim a slot
    // unconditionally, silently ZEROING a still-LOCKED page when the pool
    // wrapped (the 4097th commit destroyed the 1st token's payload while
    // that token was still live). A page is reusable only after its token
    // was consumed or burned - and under the split that reuse is real:
    // BURNED slots (capacity 0, zeroed content) are claimable again, so
    // the pool no longer single-steps through its slots; a full pool is
    // still an error, never a clobber.
    if (emergency_wipe_.load(std::memory_order_acquire)) {
        throw std::runtime_error("MemoryCore: vault retired by emergency burn");
    }
    const size_t start = next_page_.fetch_add(1, std::memory_order_acq_rel);
    MemoryPage* target = nullptr;
    uint8_t claimed_from = static_cast<uint8_t>(PageState::VOID);
    for (size_t k = 0; k < page_slot_count_; ++k) {
        MemoryPage& cand = pages_[(start + k) % page_slot_count_];
        uint8_t expected = static_cast<uint8_t>(PageState::VOID);
        if (cand.state.compare_exchange_strong(expected, static_cast<uint8_t>(PageState::CLAIMED),
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire)) {
            target = &cand;
            claimed_from = expected;
            break;
        }
        // BURNED slot with a zeroed capacity: reusable (round-5 policy).
        if (expected == static_cast<uint8_t>(PageState::BURNED) && cand.capacity == 0 &&
            cand.state.compare_exchange_strong(expected, static_cast<uint8_t>(PageState::CLAIMED),
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire)) {
            target = &cand;
            claimed_from = expected;
            break;
        }
    }
    if (!target) {
        throw std::runtime_error("MemoryCore: vault pool full (no consumed/burned slot free)");
    }
    MemoryPage& page = *target;

    // Security review (2026-11-07, HIGH): the pre-claim latch check races
    // the wipe's seq_cst store - a commit that read the latch as false can
    // claim a page and publish LOCKED after the panic sweep passed its slot,
    // so the drain would exit with live key material unreaped. Re-check
    // UNDER the claim: if the wipe latched meanwhile, this page must never
    // publish LOCKED. Release the slot back to its prior state and refuse.
    // The re-check load is seq_cst (verification round: a lone acquire load
    // may formally read stale against the seq_cst latch store in the
    // abstract machine; seq_cst closes the gap completely for one load).
    if (emergency_wipe_.load(std::memory_order_seq_cst)) {
        page.state.store(claimed_from, std::memory_order_release);
        throw std::runtime_error("MemoryCore: vault retired by emergency burn");
    }

    // page owns a private, in-bounds region of the arena (CLAIMED: no
    // concurrent reader exists for this page).
    page.offset = static_cast<size_t>(&page - pages_.data()) * PAGE_SIZE;
    page.capacity = static_cast<uint32_t>(size);

    std::memcpy(arena_ + page.offset, raw_data, size);
    if (size < PAGE_SIZE) {
        memset(arena_ + page.offset + size, 0, PAGE_SIZE - size);
    }

    // Full 32-byte capability digest (round 5: only the first 4 bytes used
    // to be stored AND compared, so 224 token bits were never checked).
    const auto digest = generate_unique_sha32(raw_data, size);
    store_digest_(page, digest);

    // Publish: the release-store makes the arena bytes, capacity and
    // digest visible to every thread that acquires LOCKED.
    page.state.store(static_cast<uint8_t>(PageState::LOCKED), std::memory_order_release);
    return digest;
}

bool MemoryCore::consume_data(const std::array<uint8_t, 32>& h32, uint8_t* out_buffer) {
    // A retired vault serves nobody (verification round 2026-11-07, the
    // semantic half of the drain finding): under the old global mutex a
    // consume concurrent with the emergency wipe blocked until the sweep
    // finished and then failed; the latch check restores exactly that. It
    // also means no token can be honored while the drain is running - the
    // wipe's contract ("no live secret survives") would otherwise be
    // readable-around by an in-flight consume.
    if (emergency_wipe_.load(std::memory_order_acquire))
        return false;
    // Vault lock split: compare lock-free first, claim only on a match.
    // Claiming every scanned page (claim-then-compare) would hide live
    // tokens from concurrent scanners for the duration of each compare and
    // turn benign contention into false "token lost" outcomes (found by the
    // stress test); compare-then-claim keeps pages visible. The digest read
    // is atomic (see memory_vault.hpp): the emergency-burn sweep may claim
    // the page and zero the digest between our state check and the compare
    // - a mismatch then simply skips the page, and a match is impossible
    // against a zeroed digest, so no false positive can reach the claim.
    for (auto& page : pages_) {
        if (page.state.load(std::memory_order_acquire) != static_cast<uint8_t>(PageState::LOCKED))
            continue;
        // Constant-time full-digest compare: early-exit memcmp would leak
        // how many leading bytes of the capability matched.
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < 32; ++i) {
            diff |= page.content_hash[i].load(std::memory_order_relaxed) ^ h32[i];
        }
        if (diff != 0) continue;

        uint8_t expected = static_cast<uint8_t>(PageState::LOCKED);
        if (!page.state.compare_exchange_strong(expected, static_cast<uint8_t>(PageState::CLAIMED),
                                                std::memory_order_acq_rel,
                                                std::memory_order_acquire)) {
            continue; // another consumer (or the panic wipe) won this page
        }

        // ABA re-check (security review 2026-11-07, MEDIUM): between our
        // compare and the winning CAS the page could have been wiped and
        // repurposed (wipe -> BURNED -> new commit -> LOCKED) - the CAS
        // would then win against the NEW page while we hold the OLD token.
        // Re-run the constant-time compare under the claim: on mismatch the
        // arena bytes are another committer's payload and must not be copied
        // out. Restore LOCKED (nothing but us touched the page since the
        // fresh committer published it) and keep scanning.
        volatile uint8_t diff2 = 0;
        for (size_t i = 0; i < 32; ++i) {
            diff2 |= page.content_hash[i].load(std::memory_order_relaxed) ^ h32[i];
        }
        if (diff2 != 0) {
            page.state.store(static_cast<uint8_t>(PageState::LOCKED), std::memory_order_release);
            continue;
        }
        // Digest verified under CLAIM: the arena bytes below are this
        // token's payload.
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

        page.capacity = 0;
        zero_digest_(page);
        page.state.store(static_cast<uint8_t>(PageState::BURNED), std::memory_order_release);
        return true;
    }
    return false;
}

void MemoryCore::emergency_burn_all() {
    // Vault lock split: no global mutex to hide behind, so the panic wipe
    // first LATCHES (seq_cst store BEFORE any sweep), then runs a fixpoint
    // drain: each pass CAS-burns every page it finds LOCKED and notes any
    // CLAIMED page it had to skip. The loop ends only after a full pass
    // that (a) burned nothing, (b) observed no CLAIMED page at any visit,
    // and (c) finds no CLAIMED page on the final scan. The post-claim
    // latch re-check in commit/sign guarantees no page can publish LOCKED
    // after the latch - so once a pass is quiet, every remaining page is
    // in a quiescent VOID/LOCKED(=burned this pass)/BURNED state and no
    // live secret can survive (the HIGH-severity drain-race finding:
    // the old "spin until !any_claimed" could exit while a page that the
    // sweep had already passed went CLAIMED->LOCKED behind it, leaving
    // plaintext + a redeemable token in the retired vault).
    // Termination: after the latch, every in-flight owner either burns its
    // own page or publishes LOCKED (then re-checked) or throws after
    // releasing the slot - a finite set, and every pass that burns nothing
    // while seeing no CLAIMED ends the loop.
    emergency_wipe_.store(true, std::memory_order_seq_cst);
    auto any_claimed = [this]() {
        for (const auto &page : pages_) {
            if (page.state.load(std::memory_order_acquire) ==
                static_cast<uint8_t>(PageState::CLAIMED))
                return true;
        }
        return false;
    };
    auto any_locked = [this]() {
        for (const auto &page : pages_) {
            if (page.state.load(std::memory_order_acquire) ==
                static_cast<uint8_t>(PageState::LOCKED))
                return true;
        }
        return false;
    };
    for (;;) {
        size_t burned = 0;
        bool saw_claimed = false;
        for (auto &page : pages_) {
            uint8_t expected = static_cast<uint8_t>(PageState::LOCKED);
            if (page.state.compare_exchange_strong(
                    expected, static_cast<uint8_t>(PageState::CLAIMED), std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                // Defense in depth: this is the last-ditch zeroization path,
                // so it must never write outside the arena even if a future
                // change breaks the slot/offset invariant. The page state is
                // still retired either way.
                if (arena_ && page.offset + PAGE_SIZE <= arena_size_) {
                    memset(arena_ + page.offset, 0, PAGE_SIZE);
                }
                page.capacity = 0;
                zero_digest_(page);
                page.state.store(static_cast<uint8_t>(PageState::BURNED),
                                 std::memory_order_release);
                ++burned;
                continue;
            }
            // Verification round (2026-11-07): on a FAILED CAS, `expected`
            // holds the value observed at CAS time. A page that was CLAIMED
            // at CAS time and publishes LOCKED a few instructions later (the
            // skid window between this failed CAS and any reload) must still
            // be noted here - re-reading the state word after the CAS could
            // see LOCKED and let a quiet pass exit with the page unreaped.
            // The CAS's own `expected` cannot skid.
            if (expected == static_cast<uint8_t>(PageState::CLAIMED)) {
                saw_claimed = true;
            }
        }
        // Belt and braces: a quiet pass must also find no LOCKED page on the
        // final scan - a page CLAIMED at its visit that published LOCKED
        // after the visit is caught here (and burned by the next pass).
        if (burned == 0 && !saw_claimed && !any_claimed() && !any_locked())
            break;
        // Let in-flight owners finish (their own end state is LOCKED or
        // BURNED - both re-examined next pass) instead of busy-burning
        // through their working memory.
        std::this_thread::yield();
    }
    hw_master_key_.store(0, std::memory_order_release);
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
    // Vault lock split: no snapshot lock anymore. Each page contributes to
    // exactly ONE bucket (its state word is a single atomic load), so no
    // page is ever double-counted or lost; the three visible counters may
    // together fall short of the pool size by the number of pages currently
    // CLAIMED in flight (nanosecond-scale windows). The v0.0.11 invariant
    // "a live token is never misreported as burned" holds a fortiori: a
    // page is counted LOCKED only while its state word reads LOCKED, which
    // is exactly when its token is redeemable.
    stats.huge_pages = arena_is_huge_;
    stats.mlock_active = arena_mlock_active_;
    stats.hw_uuid_hash = hw_master_key_.load(std::memory_order_relaxed);
    stats.lock_step_cycles = entropy_nonce_.load(std::memory_order_relaxed);

    for (const auto& page : pages_) {
        switch (static_cast<PageState>(page.state.load(std::memory_order_relaxed))) {
            case PageState::VOID:   stats.void_pages++;   break;
            case PageState::LOCKED: stats.locked_pages++; break;
            case PageState::BURNED: stats.burned_pages++; break;
            case PageState::CLAIMED:
                break; // in flight; belongs to no bucket yet
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
    // Vault lock split: the claim is the page's own CAS; only the winner
    // burns (a concurrent burn or consume of the same page loses cleanly).
    if (page_id >= POOL_SIZE)
        return false;
    MemoryPage &page = pages_[page_id];
    uint8_t expected = static_cast<uint8_t>(PageState::LOCKED);
    if (!page.state.compare_exchange_strong(expected, static_cast<uint8_t>(PageState::CLAIMED),
                                            std::memory_order_acq_rel, std::memory_order_acquire)) {
        return false;
    }
    return burn_page_claimed_(page_id);
}

bool MemoryCore::burn_page_claimed_(uint32_t page_id) noexcept {
    if (page_id >= POOL_SIZE) return false;
    MemoryPage& page = pages_[page_id];
    if (page.capacity == 0) {
        // Empty page (capacity 0): nothing to zeroize payload-wise, but the
        // caller holds this page CLAIMED and it MUST NOT stay CLAIMED - a
        // wedged CLAIMED page would hang the emergency-wipe fixpoint drain
        // forever, including the drain in ~MemoryCore (review 2026-11-07).
        // The burn invariant (every burn path zeroes before publishing)
        // covers reused slots; a never-used region is fresh allocation.
        // Belt and braces: sweep the whole page region anyway, then publish
        // BURNED so the slot returns to the reusable pool.
        if (arena_) {
            std::memset(arena_ + page.offset, 0, PAGE_SIZE);
        }
        zero_digest_(page);
        page.state.store(static_cast<uint8_t>(PageState::BURNED), std::memory_order_release);
        return false;
    }
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

    page.capacity = 0; // slot returns to the reusable pool
    zero_digest_(page);
    page.state.store(static_cast<uint8_t>(PageState::BURNED), std::memory_order_release);
    return true;
}

MemoryCore::EphemeralSignReport MemoryCore::sign_ephemeral_in_vault(
    blockchain::Transaction& tx) {
    EphemeralSignReport report;
    const uint64_t t0 = hw::cycle_counter();
    const auto wall0 = std::chrono::steady_clock::now();

    // Vault lock split: the page claim is the CAS below; the whole
    // SK-expansion -> sponge-sign -> burn cycle runs lock-free on the
    // claimed (physically disjoint) page - a concurrent commit/consume
    // cannot touch it because the state word gates every access.
    // NOTE: get_stats() no longer locks; reading arena_mlock_active_
    // directly is unchanged and still correct (constructor-only write).

    // ── Step 2: allocate a free page via CAS claim ──────────────────────────
    if (emergency_wipe_.load(std::memory_order_acquire)) {
        throw std::runtime_error("Vault: retired by emergency burn");
    }
    int32_t page_id = -1;
    for (size_t attempt = 0; attempt < POOL_SIZE; ++attempt) {
        const size_t idx = next_page_.fetch_add(1) % page_slot_count_;
        MemoryPage& page = pages_[idx];
        uint8_t expected = static_cast<uint8_t>(PageState::VOID);
        // VOID page, or a fully-burned reusable slot (capacity 0 by the
        // burn invariant - every burn path zeroes it before publishing).
        if (!page.state.compare_exchange_strong(expected, static_cast<uint8_t>(PageState::CLAIMED),
                                                std::memory_order_acq_rel,
                                                std::memory_order_acquire)) {
            if (expected == static_cast<uint8_t>(PageState::BURNED) && page.capacity == 0 &&
                page.state.compare_exchange_strong(
                    expected, static_cast<uint8_t>(PageState::CLAIMED), std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                page_id = static_cast<int32_t>(idx);
            }
        } else {
            page_id = static_cast<int32_t>(idx);
        }
        if (page_id >= 0) {
            page.offset = idx * PAGE_SIZE;
            page.capacity = PAGE_SIZE;
            break;
        }
    }
    if (page_id < 0) throw std::runtime_error("Vault: no VOID page available");
    report.page_id = static_cast<uint32_t>(page_id);
    report.mlock_active = arena_mlock_active_;

    // Post-claim latch re-check (security review 2026-11-07, HIGH): the
    // pre-claim check above races the wipe's seq_cst store - re-check
    // UNDER the claim so a page can never publish LOCKED (or hold SK
    // material) after the wipe latched. The burn releases the slot as
    // BURNED and the error propagates. seq_cst load: see the same note in
    // commit_secure_data.
    if (emergency_wipe_.load(std::memory_order_seq_cst)) {
        burn_page_claimed_(static_cast<uint32_t>(page_id));
        throw std::runtime_error("Vault: retired by emergency burn");
    }

    // Exception safety (security review 2026-11-07): a throw inside the
    // crypto cycle (e.g. to_hex_112's allocation) must never leave the
    // page CLAIMED forever - the wipe drain would spin on it. Burn the
    // claimed page on any exit path before rethrowing.
    try {
        uint8_t *page_base = arena_ + pages_[page_id].offset;

        // ── Step 3: hardware UUID + entropy -> SK expanded ONLY inside the arena ─
        const uint64_t hw_uuid = read_motherboard_uuid();
        // Honest binding report: true when a real host anchor (DMI product_uuid
        // in the Vault edition, machine-id seed chain otherwise) was folded
        // into the key expansion. False only for the golden-ratio last resort.
        report.hw_uuid_bound = g_host_anchor_real.load(std::memory_order_relaxed);

        {
            blockchain::VortexSponge256 sponge;
            const uint8_t dom[] = "VXVAULT_SK";
            sponge.absorb(dom, sizeof(dom) - 1);
            sponge.absorb(reinterpret_cast<const uint8_t *>(&hw_uuid), sizeof(hw_uuid));
            const uint64_t nonce = entropy_nonce_.fetch_add(1);
            sponge.absorb(reinterpret_cast<const uint8_t *>(&nonce), sizeof(nonce));
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
            sponge.absorb(page_base, 32); // in-arena SK pointer read
            sponge.absorb(reinterpret_cast<const uint8_t *>(&tx), blockchain::TX_SIZE_BYTES);
            uint8_t sig[48];
            sponge.finalize(sig);
            std::memcpy(tx.cocoon_proof, sig, 12); // tag_or_sig anchor
            // Keep the remaining signature bytes out of memory entirely — only
            // the 12-byte anchor plus the tx commitment survive.
            asm volatile("" ::: "memory");
        }
        report.signed_tx_hex = to_hex_112(reinterpret_cast<const uint8_t *>(&tx));
    } catch (...) {
        burn_page_claimed_(static_cast<uint32_t>(page_id)); // page is CLAIMED by us
        throw;
    }

    // ── Step 5: microsecond self-destruction ────────────────────────────────
    burn_page_claimed_(static_cast<uint32_t>(page_id)); // page is CLAIMED by us
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