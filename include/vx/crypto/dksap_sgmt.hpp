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

namespace vx::crypto::dksap {

// SGMT key for a nickname: VortexSponge256(nickname) (owner spec §2).
std::array<uint8_t, 32> sgmt_key(const std::string &nickname);

// The 32-byte on-chain leaf: sponge("VX_DKSAP_SGMT_V1" ‖ Kspend ‖ Kkem).
std::array<uint8_t, 32> sgmt_commit(const PublicKeys &pub);

// Register/refresh a nickname: writes the commitment leaf. Returns the
// new trie root.
std::array<uint8_t, 32> sgmt_register(vx::state::GaloisTrie &trie, const std::string &nickname,
                                      const PublicKeys &pub);

// Resolve + AUTHENTICATE: the claimed record must hash to the on-chain
// leaf. false = unknown nickname OR tampered/mismatched record.
bool sgmt_resolve(const vx::state::GaloisTrie &trie, const std::string &nickname,
                  const PublicKeys &claimed);

} // namespace vx::crypto::dksap
