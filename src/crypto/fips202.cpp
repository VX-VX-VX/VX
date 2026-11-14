// FIPS 202 implementation — see fips202.hpp. Keccak-f[1600] exactly as
// specified: 24 rounds of theta/rho/pi/chi/iota over 25 uint64 lanes.
#include "vx/crypto/fips202.hpp"

#include <cstring>

namespace vx::crypto::fips202 {
namespace {

// Round constants (FIPS 202, Table 2).
constexpr uint64_t kRC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

// Rotation offsets r[x][y] (FIPS 202, Table 1); indexed [x][y].
constexpr unsigned kRho[5][5] = {{0, 36, 3, 41, 18},
                                 {1, 44, 10, 45, 2},
                                 {62, 6, 43, 15, 61},
                                 {28, 55, 25, 21, 56},
                                 {27, 20, 39, 8, 14}};

constexpr uint64_t rotl64(uint64_t x, unsigned r) {
    return r == 0 ? x : (x << r) | (x >> (64 - r));
}

// Keccak-f[1600]. A[x][y] lives at lane index x + 5*y.
void keccak_f1600(uint64_t a[25]) {
    for (int round = 0; round < 24; ++round) {
        // theta
        uint64_t c[5];
        for (int x = 0; x < 5; ++x)
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (int x = 0; x < 5; ++x) {
            const uint64_t d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
            for (int y = 0; y < 5; ++y)
                a[x + 5 * y] ^= d;
        }
        // rho + pi: b[y][(2x + 3y) % 5] = rotl(a[x][y], r[x][y])
        uint64_t b[25];
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(a[x + 5 * y], kRho[x][y]);
        // chi
        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x)
                a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
        // iota
        a[0] ^= kRC[round];
    }
}

// Absorb/squeeze driver. rate = block size in bytes; pad_byte = 0x06 (SHA3)
// or 0x1f (SHAKE). squeeze_len may be 0 (fixed-digest hashes squeeze once).
struct KeccakSponge {
    uint64_t state[25]{};
    size_t rate;
    uint8_t pad_byte;

    void absorb(const uint8_t *data, size_t len) {
        size_t off = 0;
        while (off < len) {
            const size_t chunk = (len - off < rate) ? len - off : rate;
            for (size_t i = 0; i < chunk; ++i)
                state[i / 8] ^= static_cast<uint64_t>(data[off + i]) << (8 * (i % 8));
            off += chunk;
            if (chunk == rate) {
                keccak_f1600(state);
            } else {
                // Final partial block: pad now (10*1 domain handled by caller
                // via pad_byte), permute once.
                const size_t pad_pos = chunk;
                state[pad_pos / 8] ^= static_cast<uint64_t>(pad_byte) << (8 * (pad_pos % 8));
                state[(rate - 1) / 8] ^= 0x80ULL << (8 * ((rate - 1) % 8));
                keccak_f1600(state);
                return; // absorbing done
            }
        }
        // len was an exact multiple of rate: the padding block is its own.
        state[0] ^= static_cast<uint64_t>(pad_byte);
        state[(rate - 1) / 8] ^= 0x80ULL << (8 * ((rate - 1) % 8));
        keccak_f1600(state);
    }

    void squeeze(uint8_t *out, size_t out_len) {
        size_t off = 0;
        while (off < out_len) {
            const size_t chunk = (out_len - off < rate) ? out_len - off : rate;
            for (size_t i = 0; i < chunk; ++i)
                out[off + i] = static_cast<uint8_t>(state[i / 8] >> (8 * (i % 8)));
            off += chunk;
            if (off < out_len)
                keccak_f1600(state);
        }
    }
};

} // namespace

std::array<uint8_t, 32> sha3_256(const uint8_t *data, size_t len) {
    KeccakSponge s{.rate = 136, .pad_byte = 0x06};
    s.absorb(data, len);
    std::array<uint8_t, 32> out{};
    s.squeeze(out.data(), out.size());
    return out;
}

std::array<uint8_t, 64> sha3_512(const uint8_t *data, size_t len) {
    KeccakSponge s{.rate = 72, .pad_byte = 0x06};
    s.absorb(data, len);
    std::array<uint8_t, 64> out{};
    s.squeeze(out.data(), out.size());
    return out;
}

std::vector<uint8_t> shake128(const uint8_t *data, size_t len, size_t out_len) {
    KeccakSponge s{.rate = 168, .pad_byte = 0x1f};
    s.absorb(data, len);
    std::vector<uint8_t> out(out_len);
    s.squeeze(out.data(), out_len);
    return out;
}

std::vector<uint8_t> shake256(const uint8_t *data, size_t len, size_t out_len) {
    KeccakSponge s{.rate = 136, .pad_byte = 0x1f};
    s.absorb(data, len);
    std::vector<uint8_t> out(out_len);
    s.squeeze(out.data(), out_len);
    return out;
}

} // namespace vx::crypto::fips202
