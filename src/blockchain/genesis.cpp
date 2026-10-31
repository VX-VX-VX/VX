// genesis.cpp — deterministic in-process genesis builder.
// Block #0 is never shipped: every node reconstructs the same 64 KiB frame
// from the published canonical seed. 472 B header + 1 signed coinbase tx.

#include "vx/blockchain/genesis.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/math/galois_attractor.hpp"

#include <cstring>
#include <fstream>
#include <filesystem>
#include <stdexcept>

namespace vx::blockchain {

namespace {

// PUBLIC RELEASE GENESIS ATTRACTOR SEED — random test vector for Block #0
// and deterministic KATs, published for reproducibility. NEVER use for live
// keys.
const std::string& canonical_seed() {
    static const std::string seed =
        "d15c93e51137cb32d0f0ab68524e91451f0d8a7e584a52ccad833d7c9c35396c"
        "e8b9cfa766ac99c2214eb228c71099425cff0dd7f20ba6e3fe81f19b94e7c0bc"
        "66a8c37e671273e08ed9060be52c43b19e79614837d911b7418147c04b8857d5"
        "dd83fc362976394a9ceb47f946b2f70e9e94ef62ec0aeca06f280ab1ff023b08"
        "14f44d319f30cc1402d7a4e34461725f06bb83c20035906dd26f4ba2100393c7"
        "cbdbba1d1cd57ab5ec0614140f7f58687301a4f22c78f888929daf612d9e3469"
        "b2fd1f7332a634663fdac32f387c63bc0d6a4fc3e47f62b3baf0c1e0194b7868"
        "7bf978d1e0b6561501dbaa6ea17a3ad582b6e3bf4ce818823d8ce38233a2b7cf";
    return seed;
}

// Convert a 1024-bit mpz coordinate into 128 little-endian bytes.
void coord_to_le128(const mpz_class& v, uint8_t out[128]) {
    std::memset(out, 0, 128);
    mpz_class temp = v;
    mpz_class mask255 = 255;
    for (int i = 0; i < 128; ++i) {
        out[i] = static_cast<uint8_t>(mpz_class(temp & mask255).get_ui());
        temp >>= 8;
    }
}

} // namespace

std::string genesis_coinbase_receiver() {
    static const std::string nfa = [] {
        auto attractor = vx::math::VortexAttractor::run(canonical_seed(), 1000, true);
        return attractor.addressNFA;
    }();
    return nfa;
}

BlockFrame build_genesis_frame() {
    auto attractor = vx::math::VortexAttractor::run(canonical_seed(), 1000, true);

    BlockBuilder builder;
    builder.set_height(0);
    builder.set_timestamp(1761000000); // genesis unix time

    // Prev hash: all zeros for genesis
    uint8_t zero_hash[32] = {};
    builder.set_prev_hash(zero_hash);

    // Attractor coords: X(128 LE) || Y(128 LE) || Z(128 LE) = 384 B
    uint8_t coords[384];
    coord_to_le128(attractor.finalX, coords);
    coord_to_le128(attractor.finalY, coords + 128);
    coord_to_le128(attractor.finalZ, coords + 256);
    builder.set_attractor_coords(coords);

    // Coinbase: sender = "GENESIS0..." (42 B), receiver = NFA base payload
    // (42 chars, "NFA_V6_" prefix stripped), amount = 2 540 000 VX in atomic
    // units (1 VX = 10^8 atomics), cocoon_proof = sign_transaction().
    Transaction coinbase{};
    {
        const char* genesisTag = "GENESIS0";
        std::memcpy(coinbase.sender_nfa, genesisTag, 8);
        for (size_t i = 8; i < 42; ++i) coinbase.sender_nfa[i] = '0';

        const std::string& nfa = attractor.addressNFA;
        std::memcpy(coinbase.receiver_nfa, nfa.data() + 7, 42);

        uint64_t atomics = 2'540'000ULL * 100'000'000ULL; // supply 2.54M VX
        std::memcpy(coinbase.amount, &atomics, 8);        // LE, high 8 bytes 0

        sign_transaction(coinbase);
    }
    if (!builder.add_transaction(coinbase)) {
        throw std::runtime_error("genesis builder: block rejected its own coinbase");
    }
    builder.finalize(); // computes Merkle root

    BlockFrame frame{};
    auto bytes = builder.bytes();
    std::memcpy(frame.data(), bytes.data(), BLOCK_SIZE_BYTES);
    return frame;
}

void write_genesis_file(const std::string& path) {
    const BlockFrame frame = build_genesis_frame();
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        throw std::runtime_error("genesis builder: cannot write '" + path + "'");
    }
    f.write(reinterpret_cast<const char*>(frame.data()), BLOCK_SIZE_BYTES);
    if (!f) {
        throw std::runtime_error("genesis builder: short write to '" + path + "'");
    }
}

bool ensure_genesis_file(const std::string& path) {
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) return true;
    write_genesis_file(path);
    return true;
}

} // namespace vx::blockchain
