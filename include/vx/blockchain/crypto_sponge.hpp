#pragma once

#include "vx/blockchain/block.hpp"
#include <cstdint>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace vx::blockchain {

/**
 * @brief VortexSponge256: A custom, zero-dependency ARX cryptographic sponge and
 * hash function built on 64-bit limbs (uint64_t[8] = 512-bit internal state,
 * producing a 256-bit digest). Uses Golden Phi fractional expansion constants
 * mixed with 12 non-linear rounds of rotation, addition, and XOR (ARX).
 * Empirically ~50% avalanche (SAC-tested); the standing assurance is the
 * KAT/SAC/collision-smoke test suite, not a security reduction (a 12-round
 * custom ARX sponge has none — see BACKLOG 0.15).
 *
 * Streaming contract (audit 2026-11-05):
 *  - absorb(a); absorb(b) equals absorb(a||b) IFF |a| is a multiple of the
 *    32-byte rate. Signer and verifier must always mirror identical absorb
 *    call sequences; never rely on cross-call associativity otherwise.
 *  - finalize() is single-use but IDEMPOTENT: the first call absorbs the
 *    pad and caches the digest; later calls return the cached digest.
 *    absorb() after finalize() is a hard error (abort) — misuse must be
 *    loud, never silently corrupt.
 *  - Digests are little-endian-dependent (mix_block loads the block buffer
 *    as uint64_t words); no big-endian target is supported.
 *  - Known limit, frozen by the immutable genesis frame: the finalize pad
 *    does not encode the message length, so H(m) == H(m||0…0) for trailing
 *    zeros inside the final partial chunk. Safe today ONLY because every
 *    consensus preimage is a fixed-length, domain-tagged structure
 *    (enforced by PqPreimageDomainInjectivity); a variable-length field
 *    must never be hashed where length is implicit. Delivered: the v2
 *    sponge below (VortexSponge512) has length-encoded padding.
 */
class VortexSponge256 {
public:
    static constexpr size_t DIGEST_SIZE = 32;

    explicit VortexSponge256() noexcept {
        reset();
    }

    void absorb(const uint8_t* data, size_t len) noexcept {
        if (finalized_) {
            // Audit F2: absorbing after finalize would silently produce a
            // digest for a state the caller cannot reason about. Fail loud.
            std::fputs("VortexSponge256: absorb() after finalize() - misuse\n", stderr);
            std::abort();
        }
        size_t offset = 0;
        while (offset < len) {
            size_t chunk = std::min(len - offset, sizeof(block_buf_));
            std::memset(block_buf_, 0, sizeof(block_buf_));
            std::memcpy(block_buf_, data + offset, chunk);
            mix_block();
            offset += chunk;
        }
    }

    template <typename T>
    void absorb_obj(const T& obj) noexcept {
        absorb(reinterpret_cast<const uint8_t*>(&obj), sizeof(T));
    }

    void finalize(uint8_t out[DIGEST_SIZE]) noexcept {
        if (!finalized_) {
            // Final padding & absorption
            uint64_t pad = 0x80ULL;
            absorb(reinterpret_cast<const uint8_t*>(&pad), 1);

            // Extract 256 bits (4 words) into out bytes
            for (size_t i = 0; i < 4; ++i) {
                uint64_t w = state_[i];
                for (int b = 0; b < 8; ++b) {
                    digest_cache_[i * 8 + b] = static_cast<uint8_t>((w >> (b * 8)) & 0xFF);
                }
            }
            finalized_ = true;
        }
        // Audit F2: finalize is idempotent — the pad block is absorbed once
        // and the digest is served from the cache, so a double finalize (or
        // a caller finalizing in a loop) can never drift the digest.
        std::memcpy(out, digest_cache_, DIGEST_SIZE);
    }

    static void compute(const uint8_t* data, size_t len, uint8_t out[DIGEST_SIZE]) noexcept {
        VortexSponge256 sponge;
        sponge.absorb(data, len);
        sponge.finalize(out);
    }

private:
    void reset() noexcept {
        // Golden Phi constants initial state
        state_[0] = 0x9e3779b97f4a7c15ULL;
        state_[1] = 0xf39cc0605cedc834ULL;
        state_[2] = 0x1082276bf3a27251ULL;
        state_[3] = 0xf86c6a11d0c18e95ULL;
        state_[4] = 0x276707e7869666c0ULL;
        state_[5] = 0x7166e4a2e5576ac6ULL;
        state_[6] = 0xc5a08e06385cfd4fULL;
        state_[7] = 0x54d4f87a0229c15dULL;
        std::memset(block_buf_, 0, sizeof(block_buf_));
    }

    static constexpr uint64_t rotl64(uint64_t x, unsigned int r) noexcept {
        return (x << (r & 63)) | (x >> ((64 - (r & 63)) & 63));
    }

    // ChaCha-style ARX quarter-round: proven full-diffusion primitive.
    // After this, every input bit of (a,b,c,d) statistically reaches all
    // four words (addition carries + rotations + XOR feedback).
    static void quarter_round(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d) noexcept {
        a += b; d ^= a; d = rotl64(d, 16);
        c += d; b ^= c; b = rotl64(b, 12);
        a += b; d ^= a; d = rotl64(d, 8);
        c += d; b ^= c; b = rotl64(b, 7);
    }

    void mix_block() noexcept {
        // Load block into state words 4..7
        const auto* words = reinterpret_cast<const uint64_t*>(block_buf_);
        state_[4] ^= words[0];
        state_[5] ^= words[1];
        state_[6] ^= words[2];
        state_[7] ^= words[3];

        // 12 rounds; each round runs quarter-rounds over the column groups
        // (0,4,1,5)/(2,6,3,7) AND the cross groups (0,2,4,6)/(1,3,5,7),
        // so the permutation graph is fully connected — a single flipped
        // input bit reaches all 8 state words (≈50% SAC avalanche).
        // History: the original code left four INDEPENDENT 2-word chains
        // {(i, i+4)} — a flip in block word k touched digest word k alone,
        // so forged cocoon_proofs (digest bytes 0..11) verified OK.
        for (int r = 0; r < 12; ++r) {
            (void)r;
            quarter_round(state_[0], state_[4], state_[1], state_[5]);
            quarter_round(state_[2], state_[6], state_[3], state_[7]);
            quarter_round(state_[0], state_[2], state_[4], state_[6]);
            quarter_round(state_[1], state_[3], state_[5], state_[7]);
        }
    }

    uint64_t state_[8]{};
    uint8_t block_buf_[32]{};
    bool finalized_ = false;
    uint8_t digest_cache_[DIGEST_SIZE]{};
};

/**
 * @brief Cryptographic transaction signing and proof verification functions.
 */
void sign_transaction(Transaction& tx) noexcept;
bool verify_transaction_proof(const Transaction& tx) noexcept;

/**
 * @brief VortexSponge512: the v2 sponge (BACKLOG 0.15, delivered as a
 * primitive in v0.0.9). NOT wired into consensus or the frozen v1 wire —
 * it exists so the post-quantum margin target has a real, tested home
 * before any soft migration (address version v2) is designed on top.
 *
 * Design deltas vs VortexSponge256, each driven by the 0.15 margin
 * argument:
 *  - 16 x 64-bit state (1024-bit) with a 64-byte rate: capacity 512 bits,
 *    digest 512 bits -> classical preimage ~2^512, Grover ~2^256, i.e.
 *    the same wall classical 256-bit work is today (owner's standing
 *    principle). The v1 sponge could not be "widened" by squeezing more
 *    words out: 512 output bits from a 512-bit state with 256-bit
 *    capacity would be partially self-correlated, not independent.
 *  - Initial state: capacity words 0..7 keep the v1 Golden Phi constants
 *    (construction continuity); rate words 8..15 continue the same
 *    stream via splitmix64 seeded from state_[7]'s constant
 *    (0x54d4f87a0229c15d) - documented, reproducible, no hidden knobs.
 *  - Permutation: 12 rounds of ChaCha-style column+diagonal quarter-
 *    rounds over the 4x4 word matrix - the same full-diffusion argument
 *    as v1's two group families (every word feeds two distinct
 *    quarter-rounds per round; the QR graph is connected).
 *  - Length-encoded padding (the audit limit frozen into v1 is CLOSED
 *    here): finalize() absorbs 0x80, then the 128-bit little-endian
 *    message bit-length, so H(m) == H(m||0...0) is impossible for v2
 *    regardless of alignment. Absorb-after-finalize still aborts;
 *    finalize stays idempotent.
 *  - Streaming contract identical to v1: absorb(a); absorb(b) equals
 *    absorb(a||b) IFF |a| is a multiple of the 64-byte rate.
 *  - Digests are little-endian-dependent (mix_block loads uint64_t
 *    words); no big-endian target is supported.
 */
class VortexSponge512 {
public:
    static constexpr size_t DIGEST_SIZE = 64;
    static constexpr size_t RATE_SIZE = 64;

    explicit VortexSponge512() noexcept {
        reset();
    }

    void absorb(const uint8_t* data, size_t len) noexcept {
        if (finalized_) {
            // Same misuse rule as v1: fail loud, never silently corrupt.
            std::fputs("VortexSponge512: absorb() after finalize() - misuse\n", stderr);
            std::abort();
        }
        size_t offset = 0;
        while (offset < len) {
            size_t chunk = std::min(len - offset, sizeof(block_buf_));
            std::memset(block_buf_, 0, sizeof(block_buf_));
            std::memcpy(block_buf_, data + offset, chunk);
            mix_block();
            msg_bits_ += uint64_t(chunk) * 8;
            offset += chunk;
        }
    }

    template <typename T>
    void absorb_obj(const T& obj) noexcept {
        absorb(reinterpret_cast<const uint8_t*>(&obj), sizeof(T));
    }

    void finalize(uint8_t out[DIGEST_SIZE]) noexcept {
        if (!finalized_) {
            // Length-encoded padding: delimiter, then the 128-bit
            // little-endian message bit-length. Both go through the same
            // rate path as message data, so the absorbed stream is
            // unambiguous for any input length. The message length is
            // snapshotted BEFORE the pad bytes enter the sponge.
            const uint64_t bits = msg_bits_;
            uint64_t pad = 0x80ULL;
            absorb(reinterpret_cast<const uint8_t*>(&pad), 1);
            const uint8_t len_bytes[16] = {
                static_cast<uint8_t>(bits & 0xFF),
                static_cast<uint8_t>((bits >> 8) & 0xFF),
                static_cast<uint8_t>((bits >> 16) & 0xFF),
                static_cast<uint8_t>((bits >> 24) & 0xFF),
                static_cast<uint8_t>((bits >> 32) & 0xFF),
                static_cast<uint8_t>((bits >> 40) & 0xFF),
                static_cast<uint8_t>((bits >> 48) & 0xFF),
                static_cast<uint8_t>((bits >> 56) & 0xFF),
                0, 0, 0, 0, 0, 0, 0, 0, // 128-bit width: high 64 reserved
            };
            absorb(len_bytes, sizeof(len_bytes));

            // Digest = the first 8 state words (64 bytes), mirroring the
            // v1 convention (v1 outputs words 0..3 of its 8-word state).
            // Preimage ~2^512 classical / ~2^256 Grover; collision floor
            // ~2^256 by the birthday bound over the 512-bit output.
            for (size_t i = 0; i < 8; ++i) {
                uint64_t w = state_[i];
                for (int b = 0; b < 8; ++b) {
                    digest_cache_[i * 8 + b] = static_cast<uint8_t>((w >> (b * 8)) & 0xFF);
                }
            }
            finalized_ = true;
        }
        std::memcpy(out, digest_cache_, DIGEST_SIZE);
    }

    static void compute(const uint8_t* data, size_t len, uint8_t out[DIGEST_SIZE]) noexcept {
        VortexSponge512 sponge;
        sponge.absorb(data, len);
        sponge.finalize(out);
    }

private:
    void reset() noexcept {
        // Capacity words 0..7: v1 Golden Phi constants (construction
        // continuity with VortexSponge256).
        state_[0] = 0x9e3779b97f4a7c15ULL;
        state_[1] = 0xf39cc0605cedc834ULL;
        state_[2] = 0x1082276bf3a27251ULL;
        state_[3] = 0xf86c6a11d0c18e95ULL;
        state_[4] = 0x276707e7869666c0ULL;
        state_[5] = 0x7166e4a2e5576ac6ULL;
        state_[6] = 0xc5a08e06385cfd4fULL;
        state_[7] = 0x54d4f87a0229c15dULL;
        // Rate words 8..15: splitmix64 continuation seeded from state_[7].
        state_[8] = 0x496d7c86d3c4000eULL;
        state_[9] = 0x751e08b0ecdb2548ULL;
        state_[10] = 0xf4f5c5f721f14c6aULL;
        state_[11] = 0xc4ff36f927e895ecULL;
        state_[12] = 0x44f18c0086600f6eULL;
        state_[13] = 0x2884f75fdc6d6de6ULL;
        state_[14] = 0x3f471154b29cccaaULL;
        state_[15] = 0x9c053b16ccea3a8fULL;
        std::memset(block_buf_, 0, sizeof(block_buf_));
        msg_bits_ = 0;
    }

    static constexpr uint64_t rotl64(uint64_t x, unsigned int r) noexcept {
        return (x << (r & 63)) | (x >> ((64 - (r & 63)) & 63));
    }

    static void quarter_round(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d) noexcept {
        a += b; d ^= a; d = rotl64(d, 16);
        c += d; b ^= c; b = rotl64(b, 12);
        a += b; d ^= a; d = rotl64(d, 8);
        c += d; b ^= c; b = rotl64(b, 7);
    }

    void mix_block() noexcept {
        // Load the 64-byte rate block into rate words 8..15.
        const auto* words = reinterpret_cast<const uint64_t*>(block_buf_);
        for (size_t i = 0; i < 8; ++i) state_[8 + i] ^= words[i];

        // 12 rounds over the 4x4 word matrix (state_[4*r + c]): column
        // quarter-rounds then diagonal quarter-rounds - every word feeds
        // two distinct quarter-rounds per round, the ChaCha connectivity
        // argument scaled to 16 words (a single flipped input bit reaches
        // all 16 state words within one round pair).
        for (int r = 0; r < 12; ++r) {
            (void)r;
            // columns: rows of the matrix (stride 4)
            quarter_round(state_[0], state_[4], state_[8], state_[12]);
            quarter_round(state_[1], state_[5], state_[9], state_[13]);
            quarter_round(state_[2], state_[6], state_[10], state_[14]);
            quarter_round(state_[3], state_[7], state_[11], state_[15]);
            // diagonals
            quarter_round(state_[0], state_[5], state_[10], state_[15]);
            quarter_round(state_[1], state_[6], state_[11], state_[12]);
            quarter_round(state_[2], state_[7], state_[8], state_[13]);
            quarter_round(state_[3], state_[4], state_[9], state_[14]);
        }
    }

    uint64_t state_[16]{};
    uint8_t block_buf_[RATE_SIZE]{};
    uint64_t msg_bits_ = 0;
    bool finalized_ = false;
    uint8_t digest_cache_[DIGEST_SIZE]{};
};

} // namespace vx::blockchain
