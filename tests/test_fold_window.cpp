// Fold-window contract test (companion to docs/ADDRESS_SECURITY.md).
//
// Pins, as regression tests, the structural facts documented in
// "Address Security of Vortex":
//   1. xorFold reads ONLY the high 16 bytes (top 128 bits) of each trunk
//      - flipping any bit below bit 896 of a trunk leaves the address
//        digest unchanged (the 2^1792 multiplicity is structural).
//   2. Flipping a bit inside a sampled byte moves the digest in exactly
//      the two byte positions the fold formula predicts:
//      X byte k      -> digest bytes 2k and 2k+1        (mod 32)
//      Y byte 15-k   -> digest bytes 2k and 2k+1        (mod 32)
//      Z byte i      -> digest bytes 2(7i mod 16) and +1 (7 is its own
//                       inverse mod 16, so byte i is sampled exactly once)
//   3. fold -> base64url -> NFA_V6_ address reproduces the attractor's
//      own address string for the canonical seed.
#include "vx/math/galois_attractor.hpp"
#include <gmpxx.h>
#include <cassert>
#include <iostream>
#include <string>

using vx::math::VortexAttractor;

namespace {

// Index (0..15, most-significant-first) of the byte containing mpz bit
// position b in [0, 1024): byte 0 holds bits 1016..1023.
unsigned byteIndex(unsigned bit) { return (1023u - bit) / 8u; }

// Which digest byte pair a flip in trunk byte k touches.
void expectedPair(unsigned trunkByte, unsigned& evenPos, unsigned& oddPos) {
    evenPos = (2 * trunkByte) % 32;
    oddPos = (2 * trunkByte + 1) % 32;
}

unsigned differingBytes(const vx::core::Hash256& a, const vx::core::Hash256& b) {
    unsigned n = 0;
    for (size_t i = 0; i < a.size(); ++i)
        if (a[i] != b[i]) ++n;
    return n;
}

bool differsOnlyAt(const vx::core::Hash256& a, const vx::core::Hash256& b,
                   unsigned p0, unsigned p1) {
    for (size_t i = 0; i < a.size(); ++i) {
        const bool expected = (i == p0 || i == p1);
        if ((a[i] != b[i]) != expected) return false;
    }
    return true;
}

} // namespace

int main() {
    const std::string canonicalSeed =
        "d15c93e51137cb32d0f0ab68524e91451f0d8a7e584a52ccad833d7c9c35396ce8b9cfa766ac99c2214eb228c71099425cff0dd7f20ba6e3fe81f19b94e7c0bc66a8c37e671273e08ed9060be52c43b19e79614837d911b7418147c04b8857d5dd83fc362976394a9ceb47f946b2f70e9e94ef62ec0aeca06f280ab1ff023b0814f44d319f30cc1402d7a4e34461725f06bb83c20035906dd26f4ba2100393c7cbdbba1d1cd57ab5ec0614140f7f58687301a4f22c78f888929daf612d9e3469b2fd1f7332a634663fdac32f387c63bc0d6a4fc3e47f62b3baf0c1e0194b78687bf978d1e0b6561501dbaa6ea17a3ad582b6e3bf4ce818823d8ce38233a2b7cf";

    const auto r = VortexAttractor::run(canonicalSeed, 10, true,
                                        vx::core::AttractorModuli::classic());

    // (3) fold -> base64url -> NFA address reproduces the attractor result.
    const auto base = VortexAttractor::xorFold(r.finalX, r.finalY, r.finalZ);
    const std::string reconstructed =
        "NFA_V6_" + VortexAttractor::base64UrlSafe(base).substr(3);
    assert(reconstructed == r.addressNFA);
    std::cout << "  fold->address round-trip: OK (" << r.addressNFA << ")\n";

    // (1) bits below the sampled window do not touch the digest.
    for (unsigned bit : {0u, 400u, 895u}) {
        const mpz_class flipped = r.finalX ^ (mpz_class(1) << bit);
        const auto d = VortexAttractor::xorFold(flipped, r.finalY, r.finalZ);
        assert(d == base);
        std::cout << "  X bit " << bit << " (unsampled): digest unchanged\n";
    }
    {
        // Same on Y and Z at their highest unsampled bits.
        const auto dy = VortexAttractor::xorFold(r.finalX, r.finalY ^ (mpz_class(1) << 895), r.finalZ);
        const auto dz = VortexAttractor::xorFold(r.finalX, r.finalY, r.finalZ ^ (mpz_class(1) << 895));
        assert(dy == base && dz == base);
        std::cout << "  Y/Z bit 895 (unsampled): digest unchanged\n";
    }

    // (2) sampled-byte flips move exactly the predicted two digest bytes.
    for (unsigned bit : {896u, 960u, 1023u}) { // X bytes k = 15, 8, 0
        const unsigned k = byteIndex(bit);
        const auto d = VortexAttractor::xorFold(
            r.finalX ^ (mpz_class(1) << bit), r.finalY, r.finalZ);
        unsigned p0, p1;
        expectedPair(k, p0, p1);
        assert(differingBytes(base, d) == 2);
        assert(differsOnlyAt(base, d, p0, p1));
        std::cout << "  X bit " << bit << " (byte " << k << "): digest moves at "
                  << p0 << "," << p1 << " only\n";
    }
    for (unsigned bit : {896u, 1023u}) { // Y byte k -> sampled at 15-k
        const unsigned k = 15 - byteIndex(bit);
        const auto d = VortexAttractor::xorFold(
            r.finalX, r.finalY ^ (mpz_class(1) << bit), r.finalZ);
        unsigned p0, p1;
        expectedPair(k, p0, p1);
        assert(differingBytes(base, d) == 2);
        assert(differsOnlyAt(base, d, p0, p1));
        std::cout << "  Y bit " << bit << " (byte " << k << " via 15-k): digest moves at "
                  << p0 << "," << p1 << " only\n";
    }
    for (unsigned i : {0u, 5u, 15u}) { // Z byte i sampled at k = 7i mod 16
        const unsigned k = (7 * i) % 16;
        const auto d = VortexAttractor::xorFold(
            r.finalX, r.finalY, r.finalZ ^ (mpz_class(1) << (1015 - 8 * i + 3)));
        unsigned p0, p1;
        expectedPair(k, p0, p1);
        assert(differingBytes(base, d) == 2);
        assert(differsOnlyAt(base, d, p0, p1));
        std::cout << "  Z byte " << i << " (sampled at k=" << k << "): digest moves at "
                  << p0 << "," << p1 << " only\n";
    }

    std::cout << "FOLD WINDOW CONTRACT: ALL ASSERTIONS PASSED\n";
    return 0;
}
