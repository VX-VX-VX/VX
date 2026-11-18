#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// VX60-SEC M2 — Transport identity (whitebook §4.6, owner-directed 2026-11-15).
//
// The node's durable transport identity: a static ML-KEM-768 keypair whose
// PUBLIC key, hashed through the consensus sponge, IS the node_id:
//
//     node_id := VortexSponge256("VX60_STATIC_ID_V1" ‖ Kkem_static)
//
// Self-certifying (KEM-PoP): whoever holds dk_static IS this id — an
// encapsulation under a foreign pk yields no usable shared secret, so
// announcing the id without the key proves nothing. This closes the PEX
// [HIGH] spoofer-censorship hole: strikes keyed by an authenticated id
// are attributable, and the dormant gate (swarm_node.hpp) flips to
// enforcement only for sessions that PROVED key possession.
//
// NO-STUB RULE: ML-KEM-768 is KAT-gated (tests/test_ml_kem_kat.cpp, ACVP).
//
// Storage: <data_dir>/vx60_identity, 0600, O_EXCL create. Fail-closed
// verification on every load: (1) magic; (2) the stored node_id must equal
// the node_id RECOMPUTED from the stored public key (a tampered id or a
// swapped keypair is refused); (3) the (ek, dk) pair is exercised with one
// encaps/decaps roundtrip (a corrupted dk that still decapsulates to a
// DIFFERENT secret is caught). A failed load REFUSES the transport boot —
// a silent rekey would change the node_id the network knows; regeneration
// is an operator decision, never a code path.
// ─────────────────────────────────────────────────────────────────────────────

#pragma once

#include "vx/crypto/ml_kem.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/core/ct_equal.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace vx::net::vx60 {

inline constexpr size_t kVx60IdMagicLen = 8;
// Versioned magic: a future layout change gets a new magic — the old file
// is then refused, never silently reinterpreted.
inline constexpr char kVx60IdMagic[kVx60IdMagicLen] = {'V', 'X', '6', '0', 'I', 'D', 'F', '1'};

/// The file layout, no variable fields in the base record:
///   magic(8) ‖ node_id(32) ‖ ek(1184) ‖ dk(2400) = 3624 bytes.
inline constexpr size_t kVx60IdBaseSize = 8 + 32 + 1184 + 2400;

/// node_id := VortexSponge256("VX60_STATIC_ID_V1" ‖ Kkem_static). The
/// domain tag is fixed; the sponge is the consensus one (a single hash
/// across the whole tree).
inline std::array<uint8_t, 32> node_id_for(const vx::crypto::mlkem::PublicKey &static_ek) noexcept {
    std::array<uint8_t, 32> out{};
    vx::blockchain::VortexSponge256 sponge;
    sponge.absorb(reinterpret_cast<const uint8_t *>("VX60_STATIC_ID_V1"), 17);
    sponge.absorb(static_ek.data(), static_ek.size());
    sponge.finalize(out.data());
    return out;
}

/// The durable transport identity. The prev-key slot exists for the M4
/// dual-slot rotation (whitebook §4.6); M2 never populates it.
struct TransportIdentity {
    vx::crypto::mlkem::PublicKey static_ek{};
    vx::crypto::mlkem::SecretKey static_dk{};
    std::array<uint8_t, 32> node_id{};
    std::optional<vx::crypto::mlkem::PublicKey> prev_ek; // M4 slot
    std::optional<vx::crypto::mlkem::SecretKey> prev_dk; // M4 slot
    uint64_t prev_expires_unix = 0;                      // M4 slot
};

/// Key-pair consistency: one full encaps/decaps roundtrip under a CSPRNG
/// challenge. Catches a corrupted dk (implicit rejection would yield a
/// different ss) and an ek/dk pairing that was swapped or tampered.
inline bool verify_pair_consistency(const vx::crypto::mlkem::PublicKey &ek,
                                    const vx::crypto::mlkem::SecretKey &dk) noexcept {
    uint8_t m32[32];
    if (::getentropy(m32, sizeof(m32)) != 0)
        return false;
    vx::crypto::mlkem::Ciphertext ct;
    vx::crypto::mlkem::SharedSecret ss1, ss2;
    if (!vx::crypto::mlkem::encaps(ek, m32, ct, ss1))
        return false;
    vx::crypto::mlkem::decaps(dk, ct, ss2);
    return vx::core::ct_equal(ss1.data(), ss2.data(), ss1.size());
}

class TransportIdentityStore {
public:
    /// Loads <dir>/vx60_identity or creates it (0600, O_EXCL) with a fresh
    /// ML-KEM keypair. Fail-closed on every verification failure.
    static bool load_or_create(const std::string &data_dir, TransportIdentity &out,
                               std::string &err) {
        // Self-sufficient attach: create the directory if missing (same
        // posture as the banlist attach).
        std::error_code fs_ec;
        std::filesystem::create_directories(data_dir, fs_ec);
        const std::string path = (std::filesystem::path(data_dir) / "vx60_identity").string();

        struct stat st{};
        if (::stat(path.c_str(), &st) == 0) {
            return load_existing(path, out, err);
        }
        if (errno != ENOENT) {
            err = std::string("vx60_identity: stat failed: ") + std::strerror(errno);
            return false;
        }
        // Create: 0600 O_EXCL. A concurrent creator loses benignly (EEXIST)
        // and falls back to the load path — the identity is the same file.
        const int wr = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (wr < 0) {
            if (errno == EEXIST)
                return load_existing(path, out, err);
            err = std::string("vx60_identity: create failed: ") + std::strerror(errno);
            return false;
        }
        vx::crypto::mlkem::keygen(out.static_ek, out.static_dk);
        out.node_id = node_id_for(out.static_ek);
        std::vector<uint8_t> buf;
        buf.reserve(kVx60IdBaseSize);
        buf.insert(buf.end(), kVx60IdMagic, kVx60IdMagic + kVx60IdMagicLen);
        buf.insert(buf.end(), out.node_id.begin(), out.node_id.end());
        buf.insert(buf.end(), out.static_ek.begin(), out.static_ek.end());
        buf.insert(buf.end(), out.static_dk.begin(), out.static_dk.end());
        bool ok = true;
        size_t put = 0;
        while (ok && put < buf.size()) {
            const ssize_t w = ::write(wr, buf.data() + put, buf.size() - put);
            if (w <= 0) {
                if (w < 0 && errno == EINTR)
                    continue;
                ok = false;
            } else {
                put += static_cast<size_t>(w);
            }
        }
        if (ok)
            ok = ::fsync(wr) == 0;
        ::close(wr);
        if (!ok) {
            err = "vx60_identity: write/fsync failed";
            ::unlink(path.c_str()); // never leave a torn identity file
            return false;
        }
        // Belt: the freshly created identity must re-verify.
        TransportIdentity check{};
        std::string check_err;
        if (!load_existing(path, check, check_err)) {
            err = "vx60_identity: fresh identity failed re-verification: " + check_err;
            return false;
        }
        return true;
    }

private:
    static bool load_existing(const std::string &path, TransportIdentity &out, std::string &err) {
        const int fd = ::open(path.c_str(), O_RDONLY);
        if (fd < 0) {
            err = std::string("vx60_identity: open failed: ") + std::strerror(errno);
            return false;
        }
        std::vector<uint8_t> buf(kVx60IdBaseSize);
        size_t got = 0;
        bool ok = true;
        while (ok && got < buf.size()) {
            const ssize_t r = ::read(fd, buf.data() + got, buf.size() - got);
            if (r <= 0) {
                if (r < 0 && errno == EINTR)
                    continue;
                ok = false;
            } else {
                got += static_cast<size_t>(r);
            }
        }
        ::close(fd);
        if (!ok || got != buf.size()) {
            err = "vx60_identity: short read (corrupt or torn file)";
            return false;
        }
        if (std::memcmp(buf.data(), kVx60IdMagic, kVx60IdMagicLen) != 0) {
            err = "vx60_identity: wrong magic";
            return false;
        }
        std::memcpy(out.node_id.data(), buf.data() + 8, 32);
        std::memcpy(out.static_ek.data(), buf.data() + 40, 1184);
        std::memcpy(out.static_dk.data(), buf.data() + 40 + 1184, 2400);
        // Fail-closed chain:
        // (1) the stored id must equal the id RECOMPUTED from the stored pk;
        const std::array<uint8_t, 32> derived = node_id_for(out.static_ek);
        if (out.node_id != derived) {
            err = "vx60_identity: node_id mismatch (tampered id or swapped keypair)";
            return false;
        }
        // (2) the (ek, dk) pair must pass one full encaps/decaps roundtrip.
        if (!verify_pair_consistency(out.static_ek, out.static_dk)) {
            err = "vx60_identity: keypair consistency check failed";
            return false;
        }
        return true;
    }
};

} // namespace vx::net::vx60
