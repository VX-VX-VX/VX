// libFuzzer target: hostile WOTS+/XMSS witness verification.
//
// Invariant: pq_verify_wots_xmss() must return true/false for any input —
// never crash, never hang, never read out of bounds. This is the single
// most security-critical accept/reject decision in VX: a forged witness
// that crashes a node is a DoS; one that verifies is a theft.
#include "vx/crypto/pq_signature.hpp"

#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Layout: 32 bytes message digest, then the 2376-byte witness.
    constexpr size_t kNeeded = 32 + sizeof(vx::crypto::pq::PqSignatureWitness);
    if (size < kNeeded) return 0;

    std::array<uint8_t, 32> msg{};
    std::memcpy(msg.data(), data, 32);

    vx::crypto::pq::PqSignatureWitness w{};
    std::memcpy(&w, data + 32, sizeof(w));

    const bool ok = vx::crypto::pq::pq_verify_wots_xmss(msg, w);
    (void)ok; // any verdict is legal; the invariant is "no crash"
    return 0;
}
