#include "vx/crypto/key_import.hpp"
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/pq_signature.hpp"

#include <atomic>
#include <cstring>
#include <vector>

namespace vx::crypto {

namespace {

constexpr char kMagic[5] = {'V', 'X', 'K', 'I', '1'};
constexpr char kChecksumTag[] = "VX_KEY_IMPORT_CHECKSUM_V1";

// Zeroize secrets after use. explicit_bzero is preferred when the libc
// declares it; the volatile store loop is the portable fallback (volatile
// stores cannot be elided under the as-if rule), closed by a compiler
// barrier so no reorder can move the scrub past the return.
void scrub(void* p, size_t n) noexcept {
    if (p == nullptr || n == 0) return;
#if defined(__GLIBC__) && !defined(__STRICT_ANSI__)
    ::explicit_bzero(p, n);
#else
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (n--) *v++ = 0;
#endif
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

// Constant-time byte-sequence comparison (equal length inputs).
bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) noexcept {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

// Strict canonical base64url decode.
//   - alphabet A-Za-z0-9-_ only;
//   - '=' is padding and may appear only as the canonical trailing 1..2
//     characters that complete the final quantum; a '=' anywhere in the
//     body, padding longer than canonical, a non-quadruple total length or
//     an empty input is rejected;
//   - non-zero discarded bits in the final quantum are rejected (the
//     encoding must be canonical, not merely decodable);
//   - trailing garbage after a complete envelope is rejected (it changes
//     the total length / padding shape above).
bool base64url_decode(std::string_view in, std::vector<uint8_t>& out) noexcept {
    out.clear();
    if (in.empty()) return false;

    auto nib = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-') return 62;
        if (c == '_') return 63;
        return -1;
    };

    // Shape: count trailing padding, then validate the quantum layout.
    size_t body = in.size();
    size_t pad = 0;
    while (body > 0 && in[body - 1] == '=') {
        ++pad;
        --body;
    }
    if (pad > 2) return false;
    const size_t total = body + pad;
    if (total == 0 || total % 4 != 0) return false; // canonical quadruple length
    const size_t rem = body % 4;                    // body quantum remainder
    if (rem == 1) return false;                     // impossible canonical quantum
    // Zero-trust review P2-1: padding exists only as the canonical
    // completion of the final quantum — never on a complete quadruple,
    // never with the wrong width.
    if (pad != 0 && (rem == 0 || pad != 4 - rem)) return false;
    // '=' anywhere inside the body is non-canonical.
    for (size_t i = 0; i < body; ++i)
        if (in[i] == '=') return false;

    out.reserve((total / 4) * 3);
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < body; ++i) {
        const int v = nib(in[i]);
        if (v < 0) return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    // Canonical final quantum: the discarded bits must be zero.
    if (bits > 0 && (acc & ((1u << bits) - 1)) != 0) return false;
    return true;
}

void base64url_encode(const uint8_t* data, size_t n, std::string& out) {
    static const char* kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    out.clear();
    out.reserve(((n + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                           (static_cast<uint32_t>(data[i + 1]) << 8) | data[i + 2];
        out.push_back(kAlphabet[(v >> 18) & 0x3F]);
        out.push_back(kAlphabet[(v >> 12) & 0x3F]);
        out.push_back(kAlphabet[(v >> 6) & 0x3F]);
        out.push_back(kAlphabet[v & 0x3F]);
    }
    const size_t rest = n - i;
    if (rest == 1) {
        const uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(kAlphabet[(v >> 18) & 0x3F]);
        out.push_back(kAlphabet[(v >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (rest == 2) {
        const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                           (static_cast<uint32_t>(data[i + 1]) << 8);
        out.push_back(kAlphabet[(v >> 18) & 0x3F]);
        out.push_back(kAlphabet[(v >> 12) & 0x3F]);
        out.push_back(kAlphabet[(v >> 6) & 0x3F]);
        out.push_back('=');
    }
}

// Canonical LEB128 varint reader. Rejects truncation, absurd lengths and
// NON-MINIMAL (overlong) encodings - 0x80 0x00 for a value that fits in
// fewer bytes is the "non-canonical leading zero" class and fails here.
bool read_canonical_varint(const uint8_t* p, size_t avail, size_t& value,
                           size_t& consumed) noexcept {
    value = 0;
    consumed = 0;
    unsigned shift = 0;
    for (;;) {
        if (consumed >= avail || consumed >= 10) return false; // truncated / absurd
        const uint8_t b = p[consumed];
        ++consumed;
        if (shift == 63 && (b & 0x7F) > 1) return false; // would overflow size_t
        value |= static_cast<size_t>(b & 0x7F) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
    }
    // Minimality: with `consumed` bytes the value must NOT have fit in
    // (consumed - 1) bytes, i.e. it must use the top group it occupies.
    if (consumed > 1) {
        const unsigned lower_bits = 7u * static_cast<unsigned>(consumed - 1);
        if (lower_bits < 64 && (value >> lower_bits) == 0) return false;
    }
    return true;
}

} // namespace

const char* key_import_error_str(KeyImportError e) noexcept {
    switch (e) {
        case KeyImportError::Ok: return "ok";
        case KeyImportError::BadEncoding: return "bad encoding (not canonical base64url)";
        case KeyImportError::BadMagic: return "bad magic";
        case KeyImportError::UnknownKeyType: return "unknown key type";
        case KeyImportError::NonCanonicalLength: return "non-canonical length encoding";
        case KeyImportError::WrongLength: return "wrong field length";
        case KeyImportError::ChecksumMismatch: return "checksum mismatch";
        case KeyImportError::AddressMismatch: return "derived address does not match provided address";
    }
    return "unknown error";
}

std::array<uint8_t, KEY_IMPORT_ADDR_BYTES> derive_pq_address(
    const std::array<uint8_t, 32>& pq_root) noexcept {
    // Zero-trust review P1-3: an imported master SK must derive the
    // CONSENSUS PQ address byte-for-byte — blockchain::derive_pq_address,
    // tag "VXPQADDRV1", "PQA" + 39 base64url chars of Sponge(tag||root).
    // The previous local derivation used a phantom tag
    // ("VX_PQ_ADDR_DERIVE_V1") and a raw d1||d2 payload, so no imported
    // key could ever match its on-chain address.
    std::array<uint8_t, KEY_IMPORT_ADDR_BYTES> out{};
    blockchain::derive_pq_address(pq_root.data(), out.data());
    return out;
}

std::string encode_pq_key_import(const std::array<uint8_t, KEY_IMPORT_SECRET_BYTES>& master_sk,
                                 const std::array<uint8_t, KEY_IMPORT_ADDR_BYTES>& address) {
    std::vector<uint8_t> body;
    body.reserve(sizeof(kMagic) + 2 + master_sk.size() + address.size() + 4);
    body.insert(body.end(), kMagic, kMagic + sizeof(kMagic));
    body.push_back(KEY_IMPORT_TYPE_PQ_MASTER_SK);
    body.push_back(static_cast<uint8_t>(master_sk.size())); // canonical single-byte varint (32 < 128)
    body.insert(body.end(), master_sk.begin(), master_sk.end());
    body.insert(body.end(), address.begin(), address.end());

    uint8_t digest[blockchain::VortexSponge256::DIGEST_SIZE];
    const auto tag = reinterpret_cast<const uint8_t*>(kChecksumTag);
    blockchain::VortexSponge256 s;
    s.absorb(tag, sizeof(kChecksumTag) - 1);
    s.absorb(body.data(), body.size());
    s.finalize(digest);
    body.push_back(digest[0]);
    body.push_back(digest[1]);
    body.push_back(digest[2]);
    body.push_back(digest[3]);
    scrub(digest, sizeof(digest));

    std::string out;
    base64url_encode(body.data(), body.size(), out);
    scrub(body.data(), body.size());
    return out;
}

KeyImportResult import_pq_key(std::string_view encoded) noexcept {
    KeyImportResult result;

    // Zero-trust review P2-3: the canonical envelope is fixed-shape and small
    // (well under 200 bytes); refuse oversized encodings up front so a hostile
    // caller cannot drive the decoder's allocation from the input length.
    constexpr size_t kMaxEncodedLen = 4096;
    if (encoded.size() > kMaxEncodedLen) {
        result.error = KeyImportError::BadEncoding;
        return result;
    }

    // -- 1. Canonical decode --------------------------------------------------
    std::vector<uint8_t> env;
    if (!base64url_decode(encoded, env)) {
        result.error = KeyImportError::BadEncoding;
        return result;
    }

    // -- 2. Envelope structure ------------------------------------------------
    if (env.size() < sizeof(kMagic) ||
        !ct_equal(env.data(), reinterpret_cast<const uint8_t*>(kMagic), sizeof(kMagic))) {
        scrub(env.data(), env.size());
        result.error = KeyImportError::BadMagic;
        return result;
    }
    size_t off = sizeof(kMagic);
    if (off >= env.size()) {
        scrub(env.data(), env.size());
        result.error = KeyImportError::WrongLength;
        return result;
    }
    const uint8_t key_type = env[off++];
    if (key_type != KEY_IMPORT_TYPE_PQ_MASTER_SK) {
        scrub(env.data(), env.size());
        result.error = KeyImportError::UnknownKeyType;
        return result;
    }

    size_t secret_len = 0, varint_used = 0;
    if (!read_canonical_varint(env.data() + off, env.size() - off, secret_len, varint_used)) {
        scrub(env.data(), env.size());
        result.error = KeyImportError::NonCanonicalLength;
        return result;
    }
    off += varint_used;
    const size_t fixed_tail = KEY_IMPORT_SECRET_BYTES + KEY_IMPORT_ADDR_BYTES + 4;
    if (secret_len != KEY_IMPORT_SECRET_BYTES ||
        env.size() < off + fixed_tail) {
        scrub(env.data(), env.size());
        result.error = KeyImportError::WrongLength;
        return result;
    }
    const size_t addr_off = off + KEY_IMPORT_SECRET_BYTES;
    const size_t cksum_off = addr_off + KEY_IMPORT_ADDR_BYTES;
    // Anything after the checksum is trailing garbage -> wrong shape.
    if (env.size() != cksum_off + 4) {
        scrub(env.data(), env.size());
        result.error = KeyImportError::WrongLength;
        return result;
    }

    // -- 3. Constant-time checksum verification (sponge primitive) ------------
    uint8_t digest[blockchain::VortexSponge256::DIGEST_SIZE];
    const auto tag = reinterpret_cast<const uint8_t*>(kChecksumTag);
    blockchain::VortexSponge256 s;
    s.absorb(tag, sizeof(kChecksumTag) - 1);
    s.absorb(env.data(), cksum_off);
    s.finalize(digest);
    const bool cksum_ok = ct_equal(env.data() + cksum_off, digest, 4);
    scrub(digest, sizeof(digest));
    if (!cksum_ok) {
        scrub(env.data(), env.size());
        result.error = KeyImportError::ChecksumMismatch;
        return result;
    }

    // -- 4. Derive the account address from the key and match it --------------
    std::array<uint8_t, KEY_IMPORT_SECRET_BYTES> master_sk{};
    std::memcpy(master_sk.data(), env.data() + off, KEY_IMPORT_SECRET_BYTES);
    std::array<uint8_t, KEY_IMPORT_ADDR_BYTES> provided_addr{};
    std::memcpy(provided_addr.data(), env.data() + addr_off, KEY_IMPORT_ADDR_BYTES);

    std::array<uint8_t, 32> pub_seed = pq::pub_seed_from_sk(master_sk);
    const auto root = pq::xmss_root(master_sk, pub_seed);
    scrub(pub_seed.data(), pub_seed.size());

    const auto derived = derive_pq_address(root);
    std::array<uint8_t, 32> root_scrub = root;
    scrub(root_scrub.data(), root_scrub.size());

    const bool addr_ok = ct_equal(derived.data(), provided_addr.data(), KEY_IMPORT_ADDR_BYTES);
    std::array<uint8_t, KEY_IMPORT_ADDR_BYTES> derived_scrub = derived;
    scrub(derived_scrub.data(), derived_scrub.size());

    if (!addr_ok) {
        scrub(master_sk.data(), master_sk.size());
        scrub(env.data(), env.size());
        result.error = KeyImportError::AddressMismatch;
        return result;
    }

    // -- 5. Success: hand the validated key material to the wallet ------------
    result.secret = master_sk;
    result.address = provided_addr;
    scrub(master_sk.data(), master_sk.size());
    scrub(env.data(), env.size());
    result.error = KeyImportError::Ok;
    return result;
}

} // namespace vx::crypto
