#pragma once
// -----------------------------------------------------------------------------
// Key import validation (BACKLOG 0.10, C5 groundwork).
//
// Import validation protects the WALLET, not the chain - consensus never
// trusts imports; one strict road, no fast checks.
//
// What this module does: it is the single strict path a wallet uses to turn
// an encoded (textual) key import into key material, verifying every layer
// before any secret is handed out:
//   1. canonical decode   - strict base64url, canonical padding only, no
//                           trailing garbage, no non-canonical encodings;
//   2. envelope structure - magic, known key type, canonical varint length,
//                           exact field lengths (wrong lengths rejected);
//   3. checksum           - 32-bit sponge checksum over the envelope body,
//                           compared in constant time;
//   4. address match      - the PQ key root is recomputed from the secret,
//                           the account address is derived from the root,
//                           and it must equal the address carried in the
//                           envelope (a key and an address it does not own
//                           is rejected, even with a valid checksum);
//   5. zeroize            - intermediate secret buffers are scrubbed after
//                           use; on any failure the decoded secret never
//                           leaves the function.
//
// What this module does NOT do: it does not touch the ledger, the mempool
// or any consensus path. Nothing here can make the chain accept a
// transaction - block apply re-verifies witnesses against the protocol
// binding table on its own.
//
// Envelope binary layout (big-endian fields):
//   offset  size  field
//   0       5     magic "VXKI1"
//   5       1     key_type (0x01 = PQ WOTS+/XMSS master secret key)
//   6       var   canonical LEB128 varint of the secret length (must be 32;
//                 a non-minimal encoding - the "leading zero" class - is
//                 rejected, e.g. 0x80 0x00 instead of 0x00)
//   ..      32    master secret key
//   ..      42    account address payload this key must derive to
//   ..      4     checksum = first 4 bytes of
//                 Sponge256("VX_KEY_IMPORT_CHECKSUM_V1" || body above)
// The text form is strict base64url (A-Za-z0-9-_) with canonical padding.
// -----------------------------------------------------------------------------

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace vx::crypto {

inline constexpr size_t KEY_IMPORT_SECRET_BYTES = 32;
inline constexpr size_t KEY_IMPORT_ADDR_BYTES = 42;
inline constexpr uint8_t KEY_IMPORT_TYPE_PQ_MASTER_SK = 0x01;

enum class KeyImportError : int {
    Ok = 0,
    BadEncoding,         // not strict canonical base64url / empty / trailing garbage
    BadMagic,            // envelope does not start with the magic
    UnknownKeyType,      // key_type byte is not a known type
    NonCanonicalLength,  // non-minimal (overlong) or truncated varint length
    WrongLength,         // secret length != expected, or trailing field lengths wrong
    ChecksumMismatch,    // sponge checksum does not match (constant-time compare)
    AddressMismatch,     // derived address from the key != provided address
};

const char* key_import_error_str(KeyImportError e) noexcept;

/// A key import result. `secret`/`address` are meaningful only when
/// error == Ok; on every other error the caller receives zeroed buffers.
struct KeyImportResult {
    KeyImportError error = KeyImportError::Ok;
    std::array<uint8_t, KEY_IMPORT_SECRET_BYTES> secret{};
    std::array<uint8_t, KEY_IMPORT_ADDR_BYTES> address{};
};

/// Wallet-side account address derivation for a PQ account: the address is
/// a pure function of the account's XMSS root (its PQ public key). This is
/// the derivation the import path checks against; it is NOT a consensus
/// rule - consensus authorization always works from the protocol binding
/// table, never from imports.
std::array<uint8_t, KEY_IMPORT_ADDR_BYTES> derive_pq_address(
    const std::array<uint8_t, 32>& pq_root) noexcept;

/// Build a canonical import string (strict base64url envelope). Exists for
/// wallet/tooling round-trips and tests; exporting a live secret is the
/// wallet's own decision, not something the chain needs.
std::string encode_pq_key_import(const std::array<uint8_t, KEY_IMPORT_SECRET_BYTES>& master_sk,
                                 const std::array<uint8_t, KEY_IMPORT_ADDR_BYTES>& address);

/// The one strict road: decode, structurally validate, checksum-verify,
/// derive the address from the key and match it. Fails closed on every
/// deviation; secrets are zeroized after use and never leave the function
/// on failure.
KeyImportResult import_pq_key(std::string_view encoded) noexcept;

} // namespace vx::crypto
