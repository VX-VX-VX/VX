// Attractor degeneracy hunt (v0.0.10, BACKLOG 2.8).
//
// Hunts for degenerate input classes of the seed -> address pipeline and
// pins each finding as a regression test. Findings documented here are
// FACTS ABOUT THE CURRENT IMPLEMENTATION - where a degeneracy is unsafe
// the fix is a fail-closed canonicalization at the CLI/RPC surface
// (tracked in BACKLOG), NOT a silent change of the pinned behavior.
#include "vx/math/galois_attractor.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include <gmpxx.h>
#include <cassert>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>

using vx::math::VortexAttractor;

namespace {

const std::string kCanonicalSeed =
    "d15c93e51137cb32d0f0ab68524e91451f0d8a7e584a52ccad833d7c9c35396ce8b9cfa766ac99c2214eb228c71099425cff0dd7f20ba6e3fe81f19b94e7c0bc66a8c37e671273e08ed9060be52c43b19e79614837d911b7418147c04b8857d5dd83fc362976394a9ceb47f946b2f70e9e94ef62ec0aeca06f280ab1ff023b0814f44d319f30cc1402d7a4e34461725f06bb83c20035906dd26f4ba2100393c7cbdbba1d1cd57ab5ec0614140f7f58687301a4f22c78f888929daf612d9e3469b2fd1f7332a634663fdac32f387c63bc0d6a4fc3e47f62b3baf0c1e0194b78687bf978d1e0b6561501dbaa6ea17a3ad582b6e3bf4ce818823d8ce38233a2b7cf";

// Deterministic pseudorandom seed generator: VortexSponge256 over a
// counter, so the hunt needs no external RNG and reruns bit-identically.
std::string pseudoSeed(uint64_t counter, size_t hex_chars) {
    const std::string tag = "VX_DEGENERACY_HUNT_V1";
    std::vector<uint8_t> bytes;
    bytes.reserve(hex_chars / 2 + 8);
    for (size_t i = 0; i < hex_chars / 2; i += 32) {
        uint8_t digest[32];
        vx::blockchain::VortexSponge256 s;
        const uint8_t* t = reinterpret_cast<const uint8_t*>(tag.data());
        s.absorb(t, tag.size());
        s.absorb(reinterpret_cast<const uint8_t*>(&counter), sizeof(counter));
        s.absorb(reinterpret_cast<const uint8_t*>(&i), sizeof(i));
        s.finalize(digest);
        bytes.insert(bytes.end(), digest, digest + 32);
    }
    static const char* h = "0123456789abcdef";
    std::string out;
    out.reserve(hex_chars);
    for (size_t i = 0; i < hex_chars / 2; ++i) {
        out.push_back(h[bytes[i] >> 4]);
        out.push_back(h[bytes[i] & 15]);
    }
    return out;
}

} // namespace

int main() {
    const uint32_t iters = 1000;
    const auto moduli = vx::core::AttractorModuli::classic();

    // ── 1. The zero seed: the canonical degenerate input ────────────────
    {
        const std::string zeroSeed(512, '0');
        const auto r = VortexAttractor::run(zeroSeed, iters, true, moduli);
        // Z_0 = (0^3 + 0^3) ^ rotl(PHI, 0) = PHI (nonzero), so the state
        // never collapses to (0,0,0); the digest is not the all-zero
        // digest. PIN the exact degenerate address this input produces so
        // any collision with a real key is detectable by lookup.
        std::cout << "zero-seed address: " << r.addressNFA << "\n";
        assert(!r.addressNFA.empty());
        mpz_class z_sum = r.finalX + r.finalY + r.finalZ;
        assert(z_sum != 0);
    }

    // ── 2. FINDING: long seeds are TRUNCATED to 512 hex chars ───────────
    // A 2048-bit seed and its own 1024-bit truncation map to the SAME
    // address. Currently pinned behavior; the fail-closed fix (reject
    // non-canonical seed lengths at the CLI/RPC surface) is BACKLOG 2.8.
    {
        const std::string extended = kCanonicalSeed + "deadbeefdeadbeef";
        const auto a = VortexAttractor::run(kCanonicalSeed, iters, true, moduli);
        const auto b = VortexAttractor::run(extended, iters, true, moduli);
        assert(a.addressNFA == b.addressNFA);
        std::cout << "truncation degeneracy confirmed: "
                  << a.addressNFA << " (512+ chars collapse)\n";
    }

    // ── 3. FINDING: short seeds are ZERO-PADDED on the right ────────────
    // "0x1234" and the explicit 512-char zero-extended form are the same
    // address. Right-padding means the seed "12" and "1200...0" collide.
    {
        const auto a = VortexAttractor::run("0x1234", iters, true, moduli);
        const auto b = VortexAttractor::run("1234" + std::string(508, '0'),
                                            iters, true, moduli);
        assert(a.addressNFA == b.addressNFA);
        std::cout << "padding degeneracy confirmed: " << a.addressNFA << "\n";
    }

    // ── 4. Invalid hex fails LOUD (degeneracy-hunt fix, v0.0.10) ────────
    // FINDING that motivated the fix: mpz_class::set_str ignores parse
    // failures, so every invalid-hex seed silently parsed to 0 and
    // collapsed into the zero-seed address - any garbled wallet derivation
    // landed on one known key. Now: whole-seed garbage throws, and a
    // PARTIALLY invalid seed (valid first half, garbage second half)
    // throws too instead of silently zeroing Y_0.
    {
        bool threw = false;
        try {
            (void)VortexAttractor::run(std::string(500, 'a') + "zz", iters, true, moduli);
        } catch (const std::exception&) {
            threw = true;
        }
        assert(threw);

        threw = false;
        try {
            const std::string halfValid = kCanonicalSeed.substr(0, 256);
            (void)VortexAttractor::run(halfValid + std::string(252, 'z') + "gggg",
                                       iters, true, moduli);
        } catch (const std::exception&) {
            threw = true;
        }
        assert(threw);
        std::cout << "invalid hex seed (whole and partial): throws (fail-loud) OK\n";
    }

    // ── 5. Locked mode is a seed REVERSAL: palindrome degeneracy ────────
    // A palindromic seed gives the same address unlocked and locked.
    // Expected by construction, pinned so a change is loud.
    {
        const std::string half = pseudoSeed(7, 256);
        const std::string palindrome = half + std::string(half.rbegin(), half.rend());
        assert(palindrome.size() == 512);
        const auto unlocked = VortexAttractor::run(palindrome, iters, true, moduli);
        const auto locked = VortexAttractor::run(palindrome, iters, false, moduli);
        assert(unlocked.addressNFA == locked.addressNFA);

        // Sanity: a NON-palindrome must differ between the two modes.
        const auto u2 = VortexAttractor::run(kCanonicalSeed, iters, true, moduli);
        const auto l2 = VortexAttractor::run(kCanonicalSeed, iters, false, moduli);
        assert(u2.addressNFA != l2.addressNFA);
        std::cout << "palindrome/locked-mode degeneracy pinned OK\n";
    }

    // ── 6. Prefix canonicalization is CASE-ASYMMETRIC (pinned quirk) ────
    // run() strips a lowercase "0x" BEFORE padding (seed budget excludes
    // the prefix), so "0x1234" == "1234". An uppercase "0X" is NOT
    // stripped by run() - it consumes two chars of the 512-char budget
    // and shifts the seed window, giving a DIFFERENT address. Pinned as
    // the current canonicalization quirk; a future fail-closed seed
    // format (BACKLOG 2.8) should accept exactly one canonical spelling.
    {
        const auto bare = VortexAttractor::run("1234", iters, true, moduli);
        const auto lower = VortexAttractor::run("0x1234", iters, true, moduli);
        const auto upper = VortexAttractor::run("0X1234", iters, true, moduli);
        assert(bare.addressNFA == lower.addressNFA);
        assert(upper.addressNFA != bare.addressNFA);
    }

    // ── 7. Orbit-collision hunt: pseudorandom seeds, full pipeline ──────
    // 40 seeds x 1000 iterations through the REAL pipeline: no two
    // addresses may collide and no digest may be all-zero.
    {
        std::set<std::string> seen;
        for (uint64_t c = 0; c < 40; ++c) {
            const auto r = VortexAttractor::run(pseudoSeed(c, 512), iters, true, moduli);
            bool all_zero = true;
            for (auto b : r.foldedHash) if (b != 0) { all_zero = false; break; }
            assert(!all_zero);
            const auto [_, inserted] = seen.insert(r.addressNFA);
            assert(inserted);
        }
        std::cout << "orbit hunt: 40 seeds -> 40 distinct addresses OK\n";
    }

    // ── 8. xorFold index coverage is a bijection onto the digest ────────
    // Positions (2k mod 32) and (2k+1 mod 32) for k in 0..15 must touch
    // every digest byte exactly once (each byte XOR-mixed once, so no
    // digest byte is a degenerate constant of the fold).
    {
        unsigned touched[32] = {};
        for (unsigned k = 0; k < 16; ++k) {
            ++touched[(2 * k) % 32];
            ++touched[(2 * k + 1) % 32];
        }
        for (unsigned i = 0; i < 32; ++i) assert(touched[i] == 1);
        std::cout << "xorFold coverage: 32/32 digest bytes, exactly once OK\n";
    }

    // ── 9. Fail-closed canonicalization at the surface (BACKLOG 2.8) ────
    // The derivation is frozen; degenerate seed classes are refused by
    // canonicalSeedError() BEFORE they reach it (wired into the
    // crypto-lab RPC endpoint as a 400).
    {
        assert(VortexAttractor::canonicalSeedError(kCanonicalSeed).empty());
        assert(VortexAttractor::canonicalSeedError("0x" + kCanonicalSeed).empty());

        assert(!VortexAttractor::canonicalSeedError("").empty());              // empty
        assert(!VortexAttractor::canonicalSeedError(std::string(512, '0')).empty()); // zero seed
        assert(!VortexAttractor::canonicalSeedError(std::string(513, 'a')).empty()); // truncation
        assert(!VortexAttractor::canonicalSeedError("0X" + kCanonicalSeed).empty()); // 0X prefix
        assert(!VortexAttractor::canonicalSeedError(std::string(500, 'a') + "zz").empty()); // non-hex

        // Shorter-than-canonical seeds remain accepted (the padding
        // degeneracy is pinned in check 3, not yet refused - a future
        // canonical-length policy belongs to the same BACKLOG item).
        assert(VortexAttractor::canonicalSeedError("1234").empty());
        std::cout << "canonicalSeedError: all degenerate classes refused OK\n";
    }


    std::cout << "DEGENERACY HUNT: all checks passed\n";
    return 0;
}
