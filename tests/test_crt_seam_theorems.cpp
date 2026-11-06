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

    // -- T6: the cube map is a BIJECTION mod every frozen modulus ---------
    // 3 does not divide M-1 for any frozen modulus (M-1 = 1 mod 3), so
    // x -> x^3 mod M is 1-to-1: no nontrivial cube root of unity exists
    // and there is NO multiplicative (v, v*zeta) collision family beside
    // the additive DELTA fold. Corrects the earlier "3 | r-1 -> cubing
    // 3-to-1" note (confusion with v2(R-1) = 3, i.e. 8 | R-1). Pinned
    // through the real inversion path: d = 3^-1 mod (M-1) exists and
    // (x^d mod M)^3 == x for deterministic pseudo-random x.
    for (const mpz_class *m : {&moduli.p, &moduli.q, &moduli.r}) {
        assert((*m - 1) % 3 == 1);
        mpz_class d;
        assert(mpz_invert(d.get_mpz_t(), mpz_class(3).get_mpz_t(), mpz_class(*m - 1).get_mpz_t()) ==
               1);
        mpz_class x = 7;
        for (int k = 0; k < 8; ++k) {
            x = (x * 6364136223846793005UL + 1442695040888963407UL) % *m;
            mpz_class cube;
            mpz_powm(cube.get_mpz_t(), x.get_mpz_t(), mpz_class(3).get_mpz_t(), m->get_mpz_t());
            mpz_class root;
            mpz_powm(root.get_mpz_t(), cube.get_mpz_t(), d.get_mpz_t(), m->get_mpz_t());
            assert(root == x); // bijective: the cube root recovers x exactly
        }
    }
    std::cout << "T6 cube bijectivity: M-1 = 1 mod 3 for P,Q,R; inversion "
                 "round trip 8/8 per modulus OK\n";

    // -- T7: fold-zone ENTRY is constructible at step 1 (merge is not) ----
    // Z0 steering: for any chosen Y0 the residue map X0 -> derive_z0 is a
    // bijection (T6), so X0 = target^(3^-1 mod (r-1)) reproduces ANY
    // chosen Z0. With Z0 free, the step-1 arxY layer inverts algebraically
    // (Y0 = rotr(arxY ^ Z0, Z0&63) - Z0), placing arxY at an exact value.
    // Both members of the additive pair (w, w + Q) are thus constructible:
    // two distinct seeds with IDENTICAL step-1 cubeY. The step output still
    // diverges in all three coordinates - the lossless rotl paths carry
    // the difference; entry into the fold zone is free, exit (merge) is
    // not (docs/CRT_COLLISION_ANALYSIS.md section 8).
    const mpz_class w = mpz_class("deadbeefcafebabe", 16);
    const mpz_class Z0_A = mpz_class("a5a5a5a5b1b2b3b4c5c6c7c8d9dadbdc", 16);
    const mpz_class Z0_B = mpz_class("5a5a5a5a1b2b3c4d5e6f70819293a4b5", 16);
    mpz_class d_r;
    assert(mpz_invert(d_r.get_mpz_t(), mpz_class(3).get_mpz_t(),
                      mpz_class(moduli.r - 1).get_mpz_t()) == 1);
    auto steer = [&](const mpz_class &z0, const mpz_class &targetArxY) {
        const unsigned th = mpz_class(z0 & 63).get_ui();
        // rotr1024 = rotl1024 by 1024 - th (rotl1024 reduces shift mod 1024)
        mpz_class y0 = VortexAttractor::rotl1024(targetArxY ^ z0, 1024 - th) - z0;
        y0 %= two1024;
        if (y0 < 0)
            y0 += two1024;
        const mpz_class rot = VortexAttractor::rotl1024(PHI, mpz_class(y0 % 64).get_ui());
        mpz_class c = ((z0 ^ rot) % moduli.r - (y0 * y0 * y0) % moduli.r) % moduli.r;
        if (c < 0)
            c += moduli.r;
        mpz_class x0;
        mpz_powm(x0.get_mpz_t(), c.get_mpz_t(), d_r.get_mpz_t(), moduli.r.get_mpz_t());
        assert(x0 > 0 && y0 > 0); // non-degenerate trunks
        // the steering is EXACT on the real derivation primitive
        assert(VortexAttractor::derive_z0(x0, y0, moduli, PHI) == z0);
        return std::pair<mpz_class, mpz_class>{x0, y0};
    };
    assert(w + moduli.q < two1024);
    const auto [xa, ya] = steer(Z0_A, w);
    const auto [xb, yb] = steer(Z0_B, w + moduli.q);
    assert(xa != xb && ya != yb); // distinct seeds
    const auto trA = VortexAttractor::step(xa, ya, Z0_A, 1, moduli, PHI);
    const auto trB = VortexAttractor::step(xb, yb, Z0_B, 1, moduli, PHI);
    assert(trA.arxY == w);
    assert(trB.arxY == w + moduli.q);                           // exact additive fold pair
    assert(trA.cubeY == trB.cubeY);                             // THE FOLD: identical cube inputs
    assert(trA.x != trB.x && trA.y != trB.y && trA.z != trB.z); // no merge
    std::cout << "T7 constructive fold entry: seeds with arxY_B = arxY_A + Q, "
                 "cubeY equal, step output diverges OK\n";

    // -- T8: moduli certification (P1 seed-set unification, BACKLOG) ------
    // Theorem 6's hypothesis is PRIMALITY of the frozen moduli; it is
    // pinned here, not assumed. Certification: GMP mpz_probab_prime_p
    // runs trial division + `reps` Miller-Rabin rounds; the MR error
    // bound is 4^-reps, so reps = 50 documents an error probability
    // <= 4^-50 < 2^-100 for each modulus. The classic fixture set is
    // pinned COMPOSITE (definitely-composite verdict for all three) so
    // it can never silently become a derivation set, and single-set
    // discipline is pinned structurally: active_default() IS secure_crt.
    {
        const auto secure = vx::core::AttractorModuli::secure_crt();
        const auto classic = vx::core::AttractorModuli::classic();
        for (const mpz_class *m : {&secure.p, &secure.q, &secure.r}) {
            assert(mpz_probab_prime_p(m->get_mpz_t(), 50) >= 1);
        }
        for (const mpz_class *m : {&classic.p, &classic.q, &classic.r}) {
            assert(mpz_probab_prime_p(m->get_mpz_t(), 50) == 0); // composite
        }
        assert(secure.p == moduli.p && secure.q == moduli.q && secure.r == moduli.r);
        const auto active = vx::core::AttractorModuli::active_default();
        assert(active.p == secure.p && active.q == secure.q && active.r == secure.r);
        std::cout << "T8 moduli certification: secure set prime (MR error "
                     "<= 2^-100), classic set composite, single-set "
                     "discipline OK\n";
    }

    std::cout << "CRT SEAM THEOREMS: all pins passed\n";
    return 0;
}
