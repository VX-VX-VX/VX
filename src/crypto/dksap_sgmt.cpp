// DKSAP SGMT registration — see dksap_sgmt.hpp.
#include "vx/crypto/dksap_sgmt.hpp"

#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/core/ct_equal.hpp"

#include <cstring>

namespace vx::crypto::dksap {

std::array<uint8_t, 32> sgmt_key(const std::string &nickname) {
    vx::blockchain::VortexSponge256 s;
    s.absorb(reinterpret_cast<const uint8_t *>(nickname.data()), nickname.size());
    std::array<uint8_t, 32> key{};
    s.finalize(key.data());
    return key;
}

std::array<uint8_t, 32> sgmt_commit(const PublicKeys &pub) {
    vx::blockchain::VortexSponge256 s;
    const uint8_t tag[] = "VX_DKSAP_SGMT_V1";
    s.absorb(tag, sizeof(tag) - 1);
    s.absorb(pub.t_spend.data(), pub.t_spend.size());
    s.absorb(pub.kkem.data(), pub.kkem.size());
    std::array<uint8_t, 32> out{};
    s.finalize(out.data());
    return out;
}

std::array<uint8_t, 32> sgmt_register(vx::state::GaloisTrie &trie, const std::string &nickname,
                                      const PublicKeys &pub) {
    const auto key = sgmt_key(nickname);
    const auto commit = sgmt_commit(pub);
    return trie.put(key.data(), commit.data());
}

bool sgmt_resolve(const vx::state::GaloisTrie &trie, const std::string &nickname,
                  const PublicKeys &claimed) {
    const auto key = sgmt_key(nickname);
    std::array<uint8_t, 32> leaf{};
    if (!trie.get(key.data(), leaf.data()))
        return false; // unknown nickname
    const auto commit = sgmt_commit(claimed);
    // constant-time leaf comparison (the record binds an account)
    return vx::core::ct_equal(commit.data(), leaf.data(), 32);
}

} // namespace vx::crypto::dksap
