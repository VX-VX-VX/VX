// Address digest structure audit (P0 finding pin, 2026-11-06).
//
// FINDING: xorFold (src/math/galois_attractor.cpp) writes
//   out[2k]   = mixed_k,  mixed_k = x_k ^ y_(15-k) ^ z_((7k) mod 16)
//   out[2k+1] = nibble_swap(mixed_k)
// so EVERY adjacent byte pair is (b, swapnib(b)) and the 256-bit digest
// carries at most 128 bits of entropy (16 independent bytes). Only the
// TOP 128 bits of each 1024-bit final state enter the digest at all.
//
// Consequences (docs/ADDRESS_SECURITY.md section "Palindromic fold
// defect", BACKLOG P0): address space is 2^128 not 2^256 (birthday
// ~2^64 accounts), VX addresses are visually fingerprintable through
// the base64 body, and the published "2^256 fold-preimage wall" claim
// is wrong. The derivation/wire/address formats are FROZEN: the fix is
// an address-format v2 through the genesis migration protocol
// (docs/DERIVATION_MIGRATION.md), never a silent change.
//
// This suite PINS THE DEFECT deterministically: every sampled digest
// must exhibit the palindromic byte-pair structure. When the migration
// protocol lands an address v2, this assert flips and forces the
// documentation and the version marker to move with it.
#include "vx/math/galois_attractor.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>

using vx::math::VortexAttractor;

namespace {

constexpr int kSeeds = 32;

std::string pseudo_seed_hex(uint64_t counter) {
    const std::string tag = "VX_DIGEST_UNIFORMITY_AUDIT_V1";
    std::string hex;
    hex.reserve(512);
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; hex.size() < 512; ++i) {
        vx::blockchain::VortexSponge256 s;
        const uint8_t *t = reinterpret_cast<const uint8_t *>(tag.data());
        s.absorb(t, tag.size());
        s.absorb(reinterpret_cast<const uint8_t *>(&counter), sizeof(counter));
        s.absorb(reinterpret_cast<const uint8_t *>(&i), sizeof(i));
        uint8_t digest[32];
        s.finalize(digest);
        for (const uint8_t b : digest) {
            hex.push_back(h[b >> 4]);
            hex.push_back(h[b & 15]);
        }
    }
    return hex.substr(0, 512);
}

uint8_t swap_nibbles(uint8_t b) noexcept {
    return static_cast<uint8_t>(((b >> 4) | (b << 4)) & 0xFF);
}

// Minimal base64url decoder for the NFA body.
bool base64url_decode(const std::string &in, std::vector<uint8_t> &out) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z')
            return c - 'A';
        if (c >= 'a' && c <= 'z')
            return c - 'a' + 26;
        if (c >= '0' && c <= '9')
            return c - '0' + 52;
        if (c == '-')
            return 62;
        if (c == '_')
            return 63;
        return -1;
    };
    int acc = 0, bits = 0;
    out.clear();
    for (const char c : in) {
        const int v = val(c);
        if (v < 0)
            return false;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return true;
}

} // namespace

int main() {
    const auto moduli = vx::core::AttractorModuli::secure_crt();
    int palindromic = 0;

    for (uint64_t c = 0; c < kSeeds; ++c) {
        const auto r = VortexAttractor::run(pseudo_seed_hex(c), 1000, true, moduli);
        const std::array<uint8_t, 32> &d = r.foldedHash;

        // THE DEFECT, pinned: odd byte = nibble swap of the preceding even
        // byte, for every pair of the digest.
        for (size_t k = 0; k < 16; ++k) {
            assert(d[2 * k + 1] == swap_nibbles(d[2 * k]));
        }
        ++palindromic;

        // Address payload alignment artifact (42-char body -> 31 bytes,
        // low nibble of the last payload byte is display padding).
        const std::string nfa = r.addressNFA;
        assert(nfa.rfind("NFA_V6_", 0) == 0);
        std::vector<uint8_t> payload;
        assert(base64url_decode(nfa.substr(7), payload));
        assert(payload.size() == 31);
        assert((payload[30] & 0x0F) == 0);
    }

    std::cout << "ADDRESS STRUCTURE: " << palindromic << "/" << kSeeds
              << " digests palindromic (defect pinned; 128-bit effective "
                 "entropy; fix ONLY via genesis migration, address v2)\n";
    return 0;
}
