// DKSAP SGMT registration — see dksap_sgmt.hpp.
#include "vx/crypto/dksap_sgmt.hpp"

#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/core/ct_equal.hpp"

#include <cstring>

namespace vx::crypto::dksap {

std::array<uint8_t, 32> sgmt_register(vx::state::GaloisTrie &trie, const std::string &nickname,
                                      const PublicKeys &pub) {
    const auto key = sgmt_key(nickname);
    const auto commit = sgmt_commit(nickname, pub);
    return trie.put(key.data(), commit.data());
}

bool sgmt_resolve(const vx::state::GaloisTrie &trie, const std::string &nickname,
                  const PublicKeys &claimed) {
    const auto key = sgmt_key(nickname);
    std::array<uint8_t, 32> leaf{};
    if (!trie.get(key.data(), leaf.data()))
        return false; // unknown nickname
    const auto commit = sgmt_commit(nickname, claimed);
    // constant-time leaf comparison (the record binds an account)
    return vx::core::ct_equal(commit.data(), leaf.data(), 32);
}

} // namespace vx::crypto::dksap
