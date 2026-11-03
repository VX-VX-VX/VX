// libFuzzer target: hostile WOTS+/XMSS witness verification.
//
// Invariant: pq_verify_wots_xmss() must return true/false for any input —
// never crash, never hang, never read out of bounds. This is the single
// most security-critical accept/reject decision in VX: a forged witness
// that crashes a node is a DoS; one that verifies is a theft.
//
// Round-8 hardening: purely random bytes almost always fail at the first
// commitment check, so the deep paths (all 67 chain walks, the checksum
// arithmetic, the XMSS auth-path recomputation) were barely covered. This
// harness signs ONE real message at startup and treats the fuzz input as
// a targeted mutation of that structurally valid witness: a byte offset
// plus an XOR mask. Every run therefore exercises the full verify walk,
// and near-miss forgeries (a flipped chain step, a mutated auth node, a
// shifted leaf) are what actually gets explored.
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/pq_signature.hpp"

#include <cstring>
#include <vector>

namespace {

struct Seed {
    std::array<uint8_t, 32> msg{};
    vx::crypto::pq::PqSignatureWitness witness{};
};

const Seed& seed_signature() {
    static const Seed seed = [] {
        Seed s{};
        vx::blockchain::VortexSponge256::compute(
            reinterpret_cast<const uint8_t*>("VX_FUZZ_SEED_MSG_V1"), 18, s.msg.data());
        std::array<uint8_t, 32> master_sk{};
        vx::blockchain::VortexSponge256::compute(
            reinterpret_cast<const uint8_t*>("VX_FUZZ_SEED_SK_V1"), 17, master_sk.data());
        const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(master_sk);
        s.witness = vx::crypto::pq::pq_sign_message(3, 0, master_sk, pub_seed, s.msg);
        return s;
    }();
    return seed;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const Seed& seed = seed_signature();

    // Fewer than 2 bytes: verify the pristine witness (the full ACCEPT
    // path must stay crash-free too).
    if (size < 2) {
        const bool ok = vx::crypto::pq::pq_verify_wots_xmss(seed.msg, seed.witness);
        (void)ok;
        return 0;
    }

    // Mutation plan: byte 0-1 = little-endian offset into the witness
    // (mod its size), the remaining bytes = an XOR mask applied from that
    // offset. Bit 7 of byte 1 redirects the mask at the MESSAGE digest
    // instead of the witness, so forged-message/valid-witness pairs are
    // explored as well.
    vx::crypto::pq::PqSignatureWitness w = seed.witness;
    std::array<uint8_t, 32> msg = seed.msg;

    const bool target_msg = (data[1] & 0x80) != 0;
    const uint16_t off = static_cast<uint16_t>(
        (static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1] & 0x7F) << 8)));
    uint8_t* base = target_msg ? msg.data() : reinterpret_cast<uint8_t*>(&w);
    const size_t span = target_msg ? msg.size() : sizeof(vx::crypto::pq::PqSignatureWitness);
    const size_t start = static_cast<size_t>(off) % span;

    size_t i = 0;
    for (size_t d = 2; d < size; ++d, ++i) {
        if (i >= span - start) break;
        base[start + i] ^= data[d];
    }

    const bool ok = vx::crypto::pq::pq_verify_wots_xmss(msg, w);
    (void)ok; // any verdict is legal; the invariant is "no crash"
    return 0;
}
