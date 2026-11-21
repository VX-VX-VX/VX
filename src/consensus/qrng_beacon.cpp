// QRNG beacon — Phase E (0.2.4): implementation of the pure layer.
//
// Discipline notes:
//  - Every output is domain-separated under its own tag (spec §4,
//    NORMATIVE). No tag reuse across intents.
//  - The seed folds the window OLDEST FIRST so the derivation is
//    order-sensitive: {r1, r2} != {r2, r1}.
//  - verify_reveal is constant-time over the 32-byte compare path.
//  - The hardware-RNG read is getrandom(2) with no /dev/urandom
//    fallback — fail-closed into the deterministic fallback instead.

#include "vx/consensus/qrng_beacon.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>

#include <cerrno>

namespace vx::consensus::qrng {

std::array<uint8_t, 32> qrng_commit(uint8_t rng_byte) noexcept {
    blockchain::VortexSponge256 sponge;
    sponge.absorb(kTagCommit, sizeof(kTagCommit) - 1);
    sponge.absorb(&rng_byte, 1);
    std::array<uint8_t, 32> out{};
    sponge.finalize(out.data());
    return out;
}

bool verify_reveal(const std::array<uint8_t, 32> &commit, uint8_t rng_byte) noexcept {
    const auto expected = qrng_commit(rng_byte);
    // Constant-time compare: accumulate the diff, branch once.
    uint8_t diff = 0;
    for (size_t i = 0; i < expected.size(); ++i)
        diff |= static_cast<uint8_t>(expected[i] ^ commit[i]);
    return diff == 0;
}

std::array<uint8_t, 32> seed_from_window(const std::vector<uint8_t> &window) noexcept {
    std::array<uint8_t, 32> out{};
    if (window.empty())
        return out; // all-zero: the caller treats as "no seed update"
    // The length is bound as ONE byte: a window longer than 255 would
    // truncate the length and collide with a short window — refuse it
    // (fail-closed: the spec's k=8 window is the only sanctioned size).
    if (window.size() > 255)
        return out;
    blockchain::VortexSponge256 sponge;
    sponge.absorb(kTagSeed, sizeof(kTagSeed) - 1);
    const uint8_t k_le = static_cast<uint8_t>(window.size());
    sponge.absorb(&k_le, 1);       // bind the window length into the derivation
    for (const uint8_t r : window) // oldest first — order-sensitive
        sponge.absorb(&r, 1);
    sponge.finalize(out.data());
    return out;
}

bool MisconductLedger::record_mismatch(const std::array<uint8_t, 32> &producer_id,
                                       uint64_t current_height) noexcept {
    Entry *e = nullptr;
    for (auto &entry : entries) {
        if (entry.producer_id == producer_id) {
            e = &entry;
            break;
        }
    }
    if (!e) {
        entries.push_back(Entry{producer_id, 0, 0});
        e = &entries.back();
    }
    ++e->strikes;
    e->banned_until = current_height + kProducerBanBlocks;
    return e->strikes >= kEpochEscalationStrikes;
}

bool MisconductLedger::is_banned(const std::array<uint8_t, 32> &producer_id,
                                 uint64_t current_height) const noexcept {
    for (const auto &entry : entries) {
        if (entry.producer_id == producer_id)
            return entry.banned_until > current_height;
    }
    return false;
}

void MisconductLedger::reset_epoch() noexcept {
    for (auto &entry : entries)
        entry.strikes = 0; // the ban window outlives the epoch reset
}

bool read_hardware_rng(uint8_t &out) noexcept {
    // getrandom(2) blocks until the kernel CSPRNG is initialized; it is
    // the ONLY source used here. No /dev/urandom fallback — an unreadable
    // RNG degrades to the deterministic fallback, never to attacker-
    // steerable entropy.
    ssize_t n;
    do {
        n = ::getrandom(&out, 1, 0);
    } while (n < 0 && errno == EINTR);
    return n == 1;
}

uint8_t fallback_byte(const std::vector<uint8_t> &prev_window) noexcept {
    blockchain::VortexSponge256 sponge;
    sponge.absorb(kTagFallback, sizeof(kTagFallback) - 1);
    const uint8_t k_le = static_cast<uint8_t>(prev_window.size());
    sponge.absorb(&k_le, 1);
    for (const uint8_t r : prev_window)
        sponge.absorb(&r, 1);
    std::array<uint8_t, 32> out{};
    sponge.finalize(out.data());
    return out[0];
}

} // namespace vx::consensus::qrng
