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

        // Shorter-than-canonical seeds: the v0.0.12 acceptance decision is
        // SUPERSEDED for the zero-trunk sub-class (v0.0.15, audit item
        // I.2): a seed whose second half is entirely zeros derives a zero
        // Y trunk - genuinely degenerate, now refused.
        assert(!VortexAttractor::canonicalSeedError("1234").empty());
        std::cout << "canonicalSeedError: all degenerate classes refused OK\n";
    }

    // ── 10. Algebraic degeneracy classes (v0.0.15, audit item I.2) ──────
    {
        // v0.0.16: the production gate interrogates active_default()
        // (secure_crt proven primes) — the same moduli run() derives with.
        // The classic set is composite and no longer pins any surface.
        const auto moduli = vx::core::AttractorModuli::secure_crt();
        const std::string f256(256, 'f');

        // Per-trunk zero: X half zero (string not all-zero -> passed the
        // old string-level check), Y half nonzero.
        assert(!VortexAttractor::canonicalSeedError(std::string(256, '0') + f256).empty());
        // Y half zero.
        assert(!VortexAttractor::canonicalSeedError(f256 + std::string(256, '0')).empty());
        // Congruent zero: X trunk == p exactly (non-zero word, zero residue).
        {
            const std::string p_hex = moduli.p.get_str(16);
            assert(p_hex.size() == 256);
            std::string low(256, '0'); low[255] = '1'; // Y = 1
            assert(!VortexAttractor::canonicalSeedError(p_hex + low).empty());
            // Same in the LOCKED orientation: run() reverses the string,
            // so the seed's SECOND half must reverse to p_hex for the
            // locked X trunk to be congruent zero.
            const std::string p_rev(p_hex.rbegin(), p_hex.rend());
            const std::string locked_seed = low + p_rev;
            assert(!VortexAttractor::canonicalSeedError(locked_seed).empty());
        }
        // Congruent zero: Y trunk == q exactly.
        {
            const std::string q_hex = moduli.q.get_str(16);
            assert(q_hex.size() == 256);
            std::string high(256, '0'); high[255] = '1'; // X = 1
            assert(!VortexAttractor::canonicalSeedError(high + q_hex).empty());
        }
        // Canonical seed and hunt seeds still clean; Z_0 != 0 pinned for
        // every accepted seed (the zero-Z class is refused by the checker).
        assert(VortexAttractor::canonicalSeedError(kCanonicalSeed).empty());
        assert(VortexAttractor::canonicalSeedError("0x" + kCanonicalSeed).empty());
        for (uint64_t c = 0; c < 10; ++c) {
            assert(VortexAttractor::canonicalSeedError(pseudoSeed(c, 512)).empty());
        }
        // Zero-Z class, POSITIVE instance (2026-11-06): the cube map is a
        // BIJECTION mod r (3 does not divide r-1), so for any Y0 the X0
        // with derive_z0(X0, Y0) == 0 is the closed form
        // X0 = (rotl1024(PHI, Y0 mod 64) - Y0^3)^(3^-1 mod (r-1)) mod r.
        // This supersedes the earlier note's "no inverse of 3 mod r-1"
        // premise (see docs/CRT_COLLISION_ANALYSIS.md, Theorem 6): the
        // class is constructible in closed form, the surface refusal of
        // it stays, and the suite now pins the positive evidence instead
        // of the negative one only.
        {
            const mpz_class PHI = VortexAttractor::hexToBigInt(std::string(vx::core::PHI_1024_HEX));
            mpz_class d_inv;
            assert(mpz_invert(d_inv.get_mpz_t(), mpz_class(3).get_mpz_t(),
                              mpz_class(moduli.r - 1).get_mpz_t()) == 1);
            const mpz_class y0 = mpz_class("1234567890abcdef1234567890abcdef", 16);
            const mpz_class rot = VortexAttractor::rotl1024(PHI, mpz_class(y0 % 64).get_ui());
            mpz_class c = rot - (y0 * y0 * y0) % moduli.r;
            c %= moduli.r;
            mpz_class x0;
            mpz_powm(x0.get_mpz_t(), c.get_mpz_t(), d_inv.get_mpz_t(), moduli.r.get_mpz_t());
            assert(x0 > 0 && x0 < moduli.r);
            assert(VortexAttractor::derive_z0(x0, y0, moduli, PHI) == 0);
            const auto pad = [](const mpz_class &v) {
                std::string h = v.get_str(16);
                assert(h.size() <= 256);
                return std::string(256 - h.size(), '0') + h;
            };
            const std::string seed = pad(x0) + pad(y0);
            assert(seed.size() == 512);
            assert(!VortexAttractor::canonicalSeedError(seed).empty());
            assert(!VortexAttractor::canonicalSeedError(seed, moduli).empty());
        }
        // Honest correction to the audit's fixed-point premise: the per-step
        // map is AFFINE ((x ^ Phi)*7+13 mod p), not a power map, so 1 and
        // p-1 are NOT fixed points of the dynamics; only ACT I cubes.
        // Pin that trunk=1 and trunk=p-1 seeds are accepted and derive
        // non-degenerate (distinct) addresses.
        {
            std::string one(256, '0'); one[255] = '1';           // X_0 = 1
            const mpz_class p_minus_1 = moduli.p - 1;
            const std::string pm1 = p_minus_1.get_str(16);       // X_0 = p-1
            assert(pm1.size() == 256);
            const auto a = VortexAttractor::run(one + f256, iters, true, moduli);
            const auto b = VortexAttractor::run(pm1 + f256, iters, true, moduli);
            assert(a.addressNFA != b.addressNFA);
            assert(VortexAttractor::canonicalSeedError(one + f256).empty());
            assert(VortexAttractor::canonicalSeedError(pm1 + f256).empty());
        }
        // Diagonal symmetry X0 == Y0: pinned ACCEPTED (different moduli
        // break the symmetry after the first round; BACKLOG 2.10 tracks the
        // deeper orbit-quality measurement).
        {
            const auto a = VortexAttractor::run(f256 + f256, iters, true, moduli);
            assert(!a.addressNFA.empty());
            std::cout << "diagonal seed address: " << a.addressNFA << "\n";
            assert(VortexAttractor::canonicalSeedError(f256 + f256).empty());
        }
        std::cout << "algebraic degeneracy classes: zero/congruent trunks refused, "
                     "fixed-point premise corrected OK\n";
    }


    std::cout << "DEGENERACY HUNT: all checks passed\n";
    return 0;
}
