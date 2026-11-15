// DKSAP SGMT registration — the nickname → public-keys directory layer.
//
// The GaloisTrie leaf holds a 32-byte COMMITMENT of the record (the full
// record is 1216 bytes — it travels out of band, like every other bulk
// payload in this tree). The resolver's gate: a claimed record is trusted
// only when sponge(Kspend ‖ Kkem) matches the on-chain leaf — a tampered
// or stale record is refused before any stealth math happens.
#pragma once

#include "vx/crypto/dksap.hpp"
#include "vx/state/galois_trie.hpp"

#include <array>
#include <string>

#include "vx/blockchain/crypto_sponge.hpp"

namespace vx::crypto::dksap {

// SGMT key for a nickname: VortexSponge256(nickname) (owner spec §2).
// INLINE: the header-only ledger apply_block references this, so every
// target that links the ledger resolves it without the SGMT lib.
inline std::array<uint8_t, 32> sgmt_key(const std::string &nickname) {
    vx::blockchain::VortexSponge256 s;
    s.absorb(reinterpret_cast<const uint8_t *>(nickname.data()), nickname.size());
    std::array<uint8_t, 32> key{};
    s.finalize(key.data());
    return key;
}

// The 32-byte on-chain leaf. V2 (adversarial review 2026-11-15, P0): the
// NICKNAME is bound into the commitment — otherwise one digest could carry
// two candidate records with different nicknames that both commit the same
// frame leaf, and the candidate model would pick one by arrival order (two
// honest nodes registering different nicknames = consensus fork).
inline std::array<uint8_t, 32> sgmt_commit(const std::string &nickname, const PublicKeys &pub) {
    vx::blockchain::VortexSponge256 s;
    const uint8_t tag[] = "VX_DKSAP_SGMT_V2";
    s.absorb(tag, sizeof(tag) - 1);
    const auto key = sgmt_key(nickname);
    s.absorb(key.data(), key.size());
    s.absorb(pub.t_spend.data(), pub.t_spend.size());
    s.absorb(pub.kkem.data(), pub.kkem.size());
    std::array<uint8_t, 32> out{};
    s.finalize(out.data());
    return out;
}

// Register/refresh a nickname: writes the commitment leaf. Returns the
// new trie root.
std::array<uint8_t, 32> sgmt_register(vx::state::GaloisTrie &trie, const std::string &nickname,
                                      const PublicKeys &pub);

// Resolve + AUTHENTICATE: the claimed record must hash to the on-chain
// leaf. false = unknown nickname OR tampered/mismatched record.
bool sgmt_resolve(const vx::state::GaloisTrie &trie, const std::string &nickname,
                  const PublicKeys &claimed);

} // namespace vx::crypto::dksap
