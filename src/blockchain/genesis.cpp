// genesis.cpp — deterministic in-process genesis builder.
// Block #0 is never shipped: every node reconstructs the same 64 KiB frame
// from the published canonical seed. 472 B header + 1 signed coinbase tx.

#include "vx/blockchain/genesis.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/pq_signature.hpp"
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

// ── PQ seed bindings (BACKLOG 0.7) ───────────────────────────────────────────
//
// PUBLIC DEMO SEEDS — published test vectors for the canonical demo run
// (Address #2 spender, Address #3 receiver), previously local to the demo
// binary and now protocol constants so every node binds the same demo
// economy. NEVER use for live keys.
namespace {
const std::string& demo_spender_seed() {
    static const std::string seed =
        "e76a1d401b5c3b803d9e909a1c7d7b5893f89e991160bfea87d56b9292a9eca5"
        "a3656ecc660111b16d81d181f69f307b864a76d5411051863d74c41f1c9b8d60"
        "dd667f204e057ede165edc4dfdfd3ad5d31330f35667412f0a6ff87b16d55256"
        "0a500902dda48ed0d69b37f28d4f9601a5f10b28ea08510137ccfe6a6b4c96d2"
        "e99756a88b7b8b2d19253166515de608fb5c75fc44e016aa1b93b2d3fae46985"
        "fcbc581bebc4292ec095a0a2d7867a14f0554636a3176bcd2e1aa0cb7cdf5490"
        "7f87113a69b32bfd4e3ab74897dc1af388e09bd6e1dfbd83b1ba63b514fc28b8"
        "2ac7fcf56593a9078dfec7a09b53ca5db9239cdd03ab9aa1b38d2d721ce5f195";
    return seed;
}
const std::string& demo_receiver_seed() {
    static const std::string seed =
        "aa0e37b14c1157a6cfeea4036e82f03958b6be4754e88d7c4817c98933cbb5eb"
        "39f34b1493cbad810a7275f9f2a3cc36069c725ad8e20b8e031c00faa6e58984"
        "34cac3a2ab04af9acce52a3e0ee119f78ac2aaf0229955b441296b1bf225e30b"
        "b32bbe6904952ea8e99a38ec07aeda17a5a203aae0a7f0b56e9946fe28f8ccc7"
        "21f6104d749ec1c2f55a8851215942d611d952153fb0e1b2e04e93a89aafc423"
        "2f2971ea1d90abe00e5b86b61561a8adbcb0b6909f4686c033cd7fd73c3eb085"
        "3131f6c100c7d1820ec87bb05ff14b10058ca58df5ed05fb927ce3af5adc23f6"
        "1fae0a4a6065aae3d0e56ec008860385b12423b5938c31d84c5399131b6273aa";
    return seed;
}

Address address_payload_from_seed(const std::string& seed_hex) {
    const auto attractor = vx::math::VortexAttractor::run(seed_hex, 1000, true);
    Address a{};
    std::memcpy(a.data(), attractor.addressNFA.data() + 7, 42);
    return a;
}

std::array<uint8_t, 32> tag_root(const char* tag, size_t len) {
    std::array<uint8_t, 32> root{};
    VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag), len, root.data());
    return root;
}
} // namespace

const std::string& demo_spender_seed_hex() { return demo_spender_seed(); }
const std::string& demo_receiver_seed_hex() { return demo_receiver_seed(); }

const Address& genesis2_mint_receiver_payload() {
    static const Address payload = [] {
        Address a{};
        const std::string nfa = demo_spender_address_nfa(); // "NFA_V6_" + 42 bytes
        std::memcpy(a.data(), nfa.data() + 7, 42);
        return a;
    }();
    return payload;
}

std::string demo_spender_address_nfa() {
    static const std::string nfa = [] {
        return vx::math::VortexAttractor::run(demo_spender_seed(), 1000, true).addressNFA;
    }();
    return nfa;
}

std::string demo_receiver_address_nfa() {
    static const std::string nfa = [] {
        return vx::math::VortexAttractor::run(demo_receiver_seed(), 1000, true).addressNFA;
    }();
    return nfa;
}

const std::vector<PqSeedBinding>& pq_seed_bindings() {
    static const std::vector<PqSeedBinding> table = [] {
        std::vector<PqSeedBinding> v;

        // 1. Genesis receiver: OFFLINE operator key. The root is a protocol
        // constant derived from a public tag; the secret key is NOT in this
        // repository. The 2.54M VX faucet stays locked until the operator
        // spends from it with a real WOTS+/XMSS witness.
        PqSeedBinding genesis_bind{};
        genesis_bind.root = tag_root("VX_PQ_GENESIS_OFFLINE_ROOT_V1", 30);
        const std::string gen_nfa = genesis_coinbase_receiver();
        std::memcpy(genesis_bind.addr.data(), gen_nfa.data() + 7, 42);
        v.push_back(genesis_bind);

        // 2. Demo spender (Address #2): bound to the PUBLIC demo spender
        // key. The demo/testnet key is published test data (the demo signs
        // with it); the binding exists so the PQ authorization path is
        // exercised end-to-end by the demo, the RPC and the cookbook.
        std::array<uint8_t, 32> demo_sk{};
        VortexSponge256::compute(reinterpret_cast<const uint8_t*>("VX_DEMO_SPENDER_SK_V1"), 21,
                                 demo_sk.data());
        PqSeedBinding demo_bind{};
        demo_bind.root = vx::crypto::pq::xmss_root(demo_sk, vx::crypto::pq::pub_seed_from_sk(demo_sk));
        demo_bind.addr = address_payload_from_seed(demo_spender_seed());
        v.push_back(demo_bind);

        // 3. Demo receiver (Address #3): receives only in the demo; bound
        // to its own offline root so it cannot be spent with the spender's
        // key.
        PqSeedBinding recv_bind{};
        recv_bind.root = tag_root("VX_DEMO_RECEIVER_OFFLINE_ROOT_V1", 31);
        recv_bind.addr = address_payload_from_seed(demo_receiver_seed());
        v.push_back(recv_bind);

        return v;
    }();
    return table;
}

} // namespace vx::blockchain
