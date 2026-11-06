// P0 CRT seam collision analysis - deterministic pins for
// docs/CRT_COLLISION_ANALYSIS.md (owner audit directive, 2026-11-06).
//
// Pins, all against the FROZEN secure moduli set:
//   T1  Theorem 1  - fold measure DELTA(M) = 2^1024 - M per modulus,
//                    and the 2-to-1 gluing of (v, v+M) pairs;
//   T2  Theorem 2  - every one of the 1024 rotations of PHI_1024 has both
//                    a 0 and a 1 among its top 960 bits (the fact that
//                    makes the owner's O(1) construction canonical);
//   T3  Theorem 2  - the owner's O(1) canonical collision family on the
//                    P-seam lock, 10/10 instances;
//   T4  Theorem 4/G- the Conditional Involution Guard RELOCATES the fold
//                    family (20/20) while staying injective on canonical
//                    inputs - it cannot remove the fold (pigeonhole);
//   T5  Theorem 5  - trajectory fold-tail scan: fixed seeds, 1000 steps,
//                    zero tail hits on every full-range reduction.
// The derivation is frozen; this suite only pins the analyzed facts.
#include "vx/core/types.hpp"
#include "vx/math/galois_attractor.hpp"
#include <gmpxx.h>
#include <cassert>
#include <iostream>
#include <set>
#include <string>

using vx::math::VortexAttractor;

namespace {

const std::string kCanonicalSeed =
    "d15c93e51137cb32d0f0ab68524e91451f0d8a7e584a52ccad833d7c9c35396ce8b9cfa766ac99c2214eb228c71099"
    "425cff0dd7f20ba6e3fe81f19b94e7c0bc66a8c37e671273e08ed9060be52c43b19e79614837d911b7418147c04b88"
    "57d5dd83fc362976394a9ceb47f946b2f70e9e94ef62ec0aeca06f280ab1ff023b0814f44d319f30cc1402d7a4e344"
    "61725f06bb83c20035906dd26f4ba2100393c7cbdbba1d1cd57ab5ec0614140f7f58687301a4f22c78f888929daf61"
    "2d9e3469b2fd1f7332a634663fdac32f387c63bc0d6a4fc3e47f62b3baf0c1e0194b78687bf978d1e0b6561501dbaa"
    "6ea17a3ad582b6e3bf4ce818823d8ce38233a2b7cf";

bool top960_mixed(const mpz_class &v) {
    bool saw0 = false, saw1 = false;
    for (unsigned b = 64; b < 1024 && !(saw0 && saw1); ++b) {
        if (mpz_tstbit(v.get_mpz_t(), b))
            saw1 = true;
        else
            saw0 = true;
    }
    return saw0 && saw1;
}

} // namespace

int main() {
    const auto moduli = vx::core::AttractorModuli::secure_crt();
    const mpz_class two1024 = mpz_class(1) << 1024;
    const mpz_class PHI = VortexAttractor::hexToBigInt(std::string(vx::core::PHI_1024_HEX));

    // -- T1: fold measure DELTA(M) = 2^1024 - M, and pair gluing -----------
    assert(two1024 - moduli.p == (mpz_class(1) << 64) + 1747);
    assert(two1024 - moduli.q == (mpz_class(1) << 888) + 3943);
    assert(two1024 - moduli.r == (mpz_class(1) << 512) + 267799);
    const mpz_class probes[] = {mpz_class(0), mpz_class(1), (mpz_class(1) << 63) + 123,
                                (mpz_class(1) << 511) + 7};
    for (const mpz_class &v : probes) {
        assert((v % moduli.p) == ((v + moduli.p) % moduli.p));
        assert((v % moduli.q) == ((v + moduli.q) % moduli.q));
        assert((v % moduli.r) == ((v + moduli.r) % moduli.r));
    }
    std::cout << "T1 fold measure: DELTA(P)=2^64+1747, DELTA(Q)=2^888+3943, "
                 "DELTA(R)=2^512+267799; gluing pinned\n";

    // -- T2: all 1024 rotations of PHI have mixed top-960 bits -------------
    for (unsigned s = 0; s < 1024; ++s) {
        assert(top960_mixed(VortexAttractor::rotl1024(PHI, s)));
    }
    std::cout << "T2 rotations: 1024/1024 rotations have mixed top-960 bits OK\n";

    // -- T3: owner's O(1) canonical collision family on the P-seam lock ----
    const mpz_class Phi_lock = VortexAttractor::rotl1024(PHI, (1000 + 37) % 1024);
    for (int k = 0; k < 10; ++k) {
        const mpz_class u = moduli.p + k;  // u in [P, 2^1024)
        const mpz_class up = u - moduli.p; // u' = u - P
        const mpz_class x1 = u ^ Phi_lock;
        const mpz_class x2 = up ^ Phi_lock;
        assert(x1 < moduli.p && x2 < moduli.p); // both canonical
        assert(((x1 ^ Phi_lock) * 7 + 13) % moduli.p ==
               ((x2 ^ Phi_lock) * 7 + 13) % moduli.p); // lock outputs equal
    }
    std::cout << "T3 owner construction: 10/10 canonical pairs glue 2-to-1 OK\n";

    // -- T4: the Guard relocates (20/20) but is injective on canonicals ----
    // Branch-B set: B = {x : x XOR Phi >= P}, |B| = DELTA(P) (XOR bijection).
    // For every tail state v in [P, 2^1024): v XOR Phi < P is canonical
    // (Theorem 2 fact), the Guard passes v through (branch B on v XOR Phi's
    // partner... precisely: guard(v) takes mixed = v XOR Phi = x1), so the
    // glued pair becomes (x1, v) - the ORIGINAL family (x1, x2) with
    // x2 = (v-P) XOR Phi is killed. 20/20 instances pinned.
    auto guard = [&moduli, &Phi_lock](const mpz_class &x) {
        const mpz_class cand = x ^ Phi_lock;
        const mpz_class mixed = (cand < moduli.p) ? cand : x;
        // Materialize: returning the expression template directly would
        // dangle into the local `mixed` (gmpxx lazily evaluates).
        mpz_class res = mixed * 7;
        res += 13;
        res %= moduli.p;
        return res;
    };
    for (int k = 0; k < 20; ++k) {
        const mpz_class v = moduli.p + k;               // tail state
        const mpz_class x1 = v ^ Phi_lock;              // canonical partner
        const mpz_class x2 = (v - moduli.p) ^ Phi_lock; // original partner
        assert(x1 < moduli.p && x2 < moduli.p);
        assert(guard(x1) == guard(v));  // relocated fold (x1, v)
        assert(guard(x1) != guard(x2)); // original family killed
    }
    std::set<mpz_class> mixed_seen; // G: injective zone
    for (int i = 0; i < 256; ++i) {
        const mpz_class x = (i < 128) ? mpz_class(i) : moduli.p - 1 - (i - 128);
        const mpz_class cand = x ^ Phi_lock;
        const mpz_class mixed = (cand < moduli.p) ? cand : x;
        assert(mixed < moduli.p);
        assert(mixed_seen.insert(mixed).second);
    }
    std::cout << "T4 guard: relocated collisions 20/20; canonical-input "
                 "injectivity pinned OK\n";

    // -- T5: trajectory fold-tail scan (3 seeds x 1000 steps, 0 tails) -----
    std::string seeds[3] = {kCanonicalSeed, kCanonicalSeed, kCanonicalSeed};
    seeds[1].replace(0, 8, "01234567");
    seeds[2].replace(0, 8, "89abcdef");
    long long reductions = 0;
    for (const std::string &seed : seeds) {
        const std::string clean = seed.substr(0, 512);
        const mpz_class X0 = VortexAttractor::hexToBigInt(clean.substr(0, 256));
        const mpz_class Y0 = VortexAttractor::hexToBigInt(clean.substr(256, 256));
        assert(X0 < moduli.p && X0 < moduli.q && X0 < moduli.r); // z0 cubes
        assert(Y0 < moduli.r);
        ++reductions;
        mpz_class x = X0, y = Y0;
        mpz_class z = VortexAttractor::derive_z0(X0, Y0, moduli, PHI);
        for (uint32_t t = 1; t <= 1000; ++t) {
            const auto tr = VortexAttractor::step(x, y, z, t, moduli, PHI);
            assert(tr.arxX < moduli.p); // P-seam tail: 2^-959/reduction
            assert(tr.arxY < moduli.q); // Q-seam tail: 2^-136/reduction
            assert(tr.arxZ < moduli.r); // R-seam tail: 2^-512/reduction
            reductions += 3;
            x = tr.x;
            y = tr.y;
            z = tr.z;
        }
        // AKT III lock tails.
        const mpz_class y_mod64 = y & 63;
        const mpz_class Phi_lock2 = VortexAttractor::rotl1024(PHI, y_mod64.get_ui() + 1000);
        assert((x ^ Phi_lock2) < moduli.p);
        assert((y ^ Phi_lock2) < moduli.q);
        assert((z ^ Phi_lock2) < moduli.r);
        reductions += 3;
    }
    std::cout << "T5 trajectory scan: " << reductions
              << " full-range reductions across 3 pinned seeds, 0 tail hits OK\n";

    std::cout << "CRT SEAM THEOREMS: all pins passed\n";
    return 0;
}
