// Key import validation suite (BACKLOG 0.10, C5 groundwork).
//
// Covers: canonical accept + round-trip, and EVERY reject class:
// bad encoding (garbage chars, empty, trailing garbage, sloppy padding,
// non-canonical final quantum), bad magic, unknown key type,
// non-canonical length varint, wrong lengths, checksum mismatch, and the
// address mismatch (a key paired with an address it does not own).
#include "vx/crypto/key_import.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/pq_signature.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

namespace {

using vx::crypto::KEY_IMPORT_ADDR_BYTES;
using vx::crypto::KEY_IMPORT_SECRET_BYTES;
using vx::crypto::KeyImportError;

// Deterministic test key #i.
std::array<uint8_t, 32> test_sk(unsigned i) {
    std::array<uint8_t, 32> sk{};
    const std::string tag = "VX_KEY_IMPORT_TEST_SK_" + std::to_string(i);
    vx::blockchain::VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag.data()),
                                             tag.size(), sk.data());
    return sk;
}

// The address a given key legitimately derives to.
std::array<uint8_t, KEY_IMPORT_ADDR_BYTES> address_of(const std::array<uint8_t, 32>& sk) {
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(sk);
    const auto root = vx::crypto::pq::xmss_root(sk, pub_seed);
    return vx::crypto::derive_pq_address(root);
}

std::string encode(const std::array<uint8_t, 32>& sk,
                   const std::array<uint8_t, KEY_IMPORT_ADDR_BYTES>& addr) {
    return vx::crypto::encode_pq_key_import(sk, addr);
}

} // namespace

TEST(VortexKeyImportTest, CanonicalAcceptAndRoundTrip) {
    const auto sk = test_sk(1);
    const auto addr = address_of(sk);
    const std::string enc = encode(sk, addr);
    EXPECT_FALSE(enc.empty());

    const auto r = vx::crypto::import_pq_key(enc);
    ASSERT_EQ(r.error, KeyImportError::Ok) << vx::crypto::key_import_error_str(r.error);
    EXPECT_EQ(r.secret, sk);
    EXPECT_EQ(r.address, addr);

    // Determinism: the same import string decodes identically every time.
    const auto r2 = vx::crypto::import_pq_key(enc);
    ASSERT_EQ(r2.error, KeyImportError::Ok);
    EXPECT_EQ(r2.secret, r.secret);
    EXPECT_EQ(r2.address, r.address);
}

TEST(VortexKeyImportTest, RejectsBadEncoding) {
    const auto sk = test_sk(2);
    const auto addr = address_of(sk);
    const std::string good = encode(sk, addr);

    // Empty and non-alphabet characters.
    EXPECT_EQ(vx::crypto::import_pq_key("").error, KeyImportError::BadEncoding);
    EXPECT_EQ(vx::crypto::import_pq_key("!!!!").error, KeyImportError::BadEncoding);
    // '+' and '/' are standard base64, not base64url.
    EXPECT_EQ(vx::crypto::import_pq_key("+/+/+/+/").error, KeyImportError::BadEncoding);
    // Trailing garbage after a complete envelope.
    EXPECT_EQ(vx::crypto::import_pq_key(good + "A").error, KeyImportError::BadEncoding);
    EXPECT_EQ(vx::crypto::import_pq_key(good + "garbage").error, KeyImportError::BadEncoding);
    // Sloppy padding: an extra '=' breaks the canonical shape.
    EXPECT_EQ(vx::crypto::import_pq_key(good + "=").error, KeyImportError::BadEncoding);
    // Not a multiple of four.
    EXPECT_EQ(vx::crypto::import_pq_key("AAAAAAA").error, KeyImportError::BadEncoding);
}

TEST(VortexKeyImportTest, RejectsNonCanonicalFinalBits) {
    // "AB" alone decodes to 1 byte; flipping the low discarded bits (e.g.
    // "AB^" with a char that keeps the same payload bits set) must fail.
    // "AB" -> payload byte 0x00 with 4 discarded zero bits; "AB8" is the
    // same decoded prefix with non-zero discarded bits.
    EXPECT_EQ(vx::crypto::import_pq_key("AB").error, KeyImportError::BadEncoding);
    EXPECT_EQ(vx::crypto::import_pq_key("AB8").error, KeyImportError::BadEncoding);

    // Round-2 review: the two inputs above are rejected EARLIER, by the
    // total % 4 shape check, so the discarded-bits rule itself was never
    // exercised. Covering inputs must have canonical QUADRUPLE length with
    // a 2-char final quantum: "AAAAAB==" (body 6, pad 2) — last data char
    // 'B' (=1) carries non-zero low discarded bits -> BadEncoding; the
    // all-zero twin "AAAAAA==" is canonical and must pass the decoder (it
    // then fails later, at the magic check).
    EXPECT_EQ(vx::crypto::import_pq_key("AAAAAB==").error, KeyImportError::BadEncoding);
    EXPECT_EQ(vx::crypto::import_pq_key("AAAAAA==").error, KeyImportError::BadMagic);
}

TEST(VortexKeyImportTest, RejectsBadMagic) {
    const auto sk = test_sk(3);
    const auto addr = address_of(sk);
    const std::string good = encode(sk, addr);
    // Corrupt one magic character while keeping the checksum valid for the
    // mutated body: rebuild the envelope from scratch with a wrong magic.
    // Simpler valid-checksum approach: encode() then flip a leading char
    // and rely on the checksum failing last - but the magic check runs
    // FIRST, so craft a short wrong-magic blob with valid base64 shape.
    EXPECT_EQ(vx::crypto::import_pq_key("AAAA" + good.substr(4)).error, KeyImportError::BadMagic);
    // Truncated envelope (shorter than the magic).
    EXPECT_EQ(vx::crypto::import_pq_key(good.substr(0, 3) + "AAAA").error, KeyImportError::BadEncoding);
}

TEST(VortexKeyImportTest, RejectsUnknownKeyType) {
    // Hand-build an envelope body with an unknown key type and a valid
    // checksum for THAT body: the type check must fire before anything else
    // about the payload matters.
    std::vector<uint8_t> body;
    const char magic[5] = {'V', 'X', 'K', 'I', '1'};
    body.insert(body.end(), magic, magic + 5);
    body.push_back(0x7F); // unknown key type
    body.push_back(32);   // canonical varint
    const auto sk = test_sk(4);
    body.insert(body.end(), sk.begin(), sk.end());
    std::array<uint8_t, 42> addr{};
    std::memcpy(addr.data(), "UNKNOWN_TYPE_ADDR_000000000000000000000000", 42);
    body.insert(body.end(), addr.begin(), addr.end());
    uint8_t digest[32];
    const char tag[] = "VX_KEY_IMPORT_CHECKSUM_V1";
    vx::blockchain::VortexSponge256 s;
    s.absorb(reinterpret_cast<const uint8_t*>(tag), sizeof(tag) - 1);
    s.absorb(body.data(), body.size());
    s.finalize(digest);
    body.push_back(digest[0]);
    body.push_back(digest[1]);
    body.push_back(digest[2]);
    body.push_back(digest[3]);

    std::string enc;
    // reuse the public encoder is impossible for a wrong type; encode the
    // body through the same base64url the module uses by encoding a valid
    // envelope and swapping prefixes is messy - use a tiny local encoder.
    static const char* alpha =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (size_t i = 0; i + 3 <= body.size(); i += 3) {
        const uint32_t v = (uint32_t(body[i]) << 16) | (uint32_t(body[i + 1]) << 8) | body[i + 2];
        enc.push_back(alpha[(v >> 18) & 0x3F]);
        enc.push_back(alpha[(v >> 12) & 0x3F]);
        enc.push_back(alpha[(v >> 6) & 0x3F]);
        enc.push_back(alpha[v & 0x3F]);
    }
    const size_t rest = body.size() % 3;
    if (rest != 0) {
        const size_t i = body.size() - rest;
        uint32_t v = uint32_t(body[i]) << 16;
        if (rest == 2) v |= uint32_t(body[i + 1]) << 8;
        enc.push_back(alpha[(v >> 18) & 0x3F]);
        enc.push_back(alpha[(v >> 12) & 0x3F]);
        enc.push_back(rest == 2 ? alpha[(v >> 6) & 0x3F] : '=');
        enc.push_back('=');
    }

    const auto r = vx::crypto::import_pq_key(enc);
    EXPECT_EQ(r.error, KeyImportError::UnknownKeyType);
}

TEST(VortexKeyImportTest, RejectsNonCanonicalLengthVarint) {
    // The "non-canonical leading zero" class: length 32 encoded as the
    // overlong 0xA0 0x00 (two bytes encoding the value 32 that fits in one)
    // with a VALID checksum for that body. Must be rejected as
    // non-canonical, not silently accepted as 32.
    std::vector<uint8_t> body;
    const char magic[5] = {'V', 'X', 'K', 'I', '1'};
    body.insert(body.end(), magic, magic + 5);
    body.push_back(0x01); // PQ master SK
    body.push_back(0xA0); // overlong varint...
    body.push_back(0x00); // ...32 in two bytes (non-minimal)
    const auto sk = test_sk(5);
    body.insert(body.end(), sk.begin(), sk.end());
    const auto addr = address_of(sk);
    body.insert(body.end(), addr.begin(), addr.end());
    uint8_t digest[32];
    const char tag[] = "VX_KEY_IMPORT_CHECKSUM_V1";
    vx::blockchain::VortexSponge256 s;
    s.absorb(reinterpret_cast<const uint8_t*>(tag), sizeof(tag) - 1);
    s.absorb(body.data(), body.size());
    s.finalize(digest);
    body.push_back(digest[0]);
    body.push_back(digest[1]);
    body.push_back(digest[2]);
    body.push_back(digest[3]);

    static const char* alpha =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string enc;
    for (size_t i = 0; i + 3 <= body.size(); i += 3) {
        const uint32_t v = (uint32_t(body[i]) << 16) | (uint32_t(body[i + 1]) << 8) | body[i + 2];
        enc.push_back(alpha[(v >> 18) & 0x3F]);
        enc.push_back(alpha[(v >> 12) & 0x3F]);
        enc.push_back(alpha[(v >> 6) & 0x3F]);
        enc.push_back(alpha[v & 0x3F]);
    }
    const size_t rest = body.size() % 3;
    if (rest != 0) {
        const size_t i = body.size() - rest;
        uint32_t v = uint32_t(body[i]) << 16;
        if (rest == 2) v |= uint32_t(body[i + 1]) << 8;
        enc.push_back(alpha[(v >> 18) & 0x3F]);
        enc.push_back(alpha[(v >> 12) & 0x3F]);
        enc.push_back(rest == 2 ? alpha[(v >> 6) & 0x3F] : '=');
        enc.push_back('=');
    }

    const auto r = vx::crypto::import_pq_key(enc);
    EXPECT_EQ(r.error, KeyImportError::NonCanonicalLength);
}

TEST(VortexKeyImportTest, RejectsWrongLengths) {
    const auto sk = test_sk(6);
    const auto addr = address_of(sk);
    const std::string good = encode(sk, addr);

    // A 31-byte secret (varint 31, one byte short): craft by re-encoding a
    // hand envelope with a wrong secret length and a matching checksum.
    auto build = [&](size_t declared_len, const std::array<uint8_t, 32>& sk_in,
                     const std::array<uint8_t, 42>& addr_in) {
        std::vector<uint8_t> body;
        const char magic[5] = {'V', 'X', 'K', 'I', '1'};
        body.insert(body.end(), magic, magic + 5);
        body.push_back(0x01);
        body.push_back(static_cast<uint8_t>(declared_len));
        for (size_t i = 0; i < declared_len && i < 32; ++i) body.push_back(sk_in[i]);
        body.insert(body.end(), addr_in.begin(), addr_in.end());
        uint8_t digest[32];
        const char tag[] = "VX_KEY_IMPORT_CHECKSUM_V1";
        vx::blockchain::VortexSponge256 s;
        s.absorb(reinterpret_cast<const uint8_t*>(tag), sizeof(tag) - 1);
        s.absorb(body.data(), body.size());
        s.finalize(digest);
        body.push_back(digest[0]);
        body.push_back(digest[1]);
        body.push_back(digest[2]);
        body.push_back(digest[3]);
        static const char* alpha =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string enc;
        for (size_t i = 0; i + 3 <= body.size(); i += 3) {
            const uint32_t v = (uint32_t(body[i]) << 16) | (uint32_t(body[i + 1]) << 8) | body[i + 2];
            enc.push_back(alpha[(v >> 18) & 0x3F]);
            enc.push_back(alpha[(v >> 12) & 0x3F]);
            enc.push_back(alpha[(v >> 6) & 0x3F]);
            enc.push_back(alpha[v & 0x3F]);
        }
        const size_t rest = body.size() % 3;
        if (rest != 0) {
            const size_t i = body.size() - rest;
            uint32_t v = uint32_t(body[i]) << 16;
            if (rest == 2) v |= uint32_t(body[i + 1]) << 8;
            enc.push_back(alpha[(v >> 18) & 0x3F]);
            enc.push_back(alpha[(v >> 12) & 0x3F]);
            enc.push_back(rest == 2 ? alpha[(v >> 6) & 0x3F] : '=');
            enc.push_back('=');
        }
        return enc;
    };
    // 31-byte secret with a valid checksum: wrong length class.
    EXPECT_EQ(vx::crypto::import_pq_key(build(31, sk, addr)).error, KeyImportError::WrongLength);
    // 33-byte declared secret (body carries 32; the tail shifts): wrong length.
    EXPECT_EQ(vx::crypto::import_pq_key(build(33, sk, addr)).error, KeyImportError::WrongLength);
    // Truncated good envelope: last quantum dropped -> trailing shape wrong.
    EXPECT_EQ(vx::crypto::import_pq_key(good.substr(0, good.size() - 4)).error,
              KeyImportError::WrongLength);
}

TEST(VortexKeyImportTest, RejectsChecksumMismatch) {
    const auto sk = test_sk(7);
    const auto addr = address_of(sk);
    const std::string good = encode(sk, addr);

    // Flip one base64 character inside a BODY quantum: the envelope shape
    // stays canonical, only a few body bytes change, so the checksum no
    // longer matches.
    std::string bad_body = good;
    ASSERT_GT(bad_body.size(), 40u);
    bad_body[40] = (bad_body[40] == 'A') ? 'B' : 'A';
    EXPECT_EQ(vx::crypto::import_pq_key(bad_body).error, KeyImportError::ChecksumMismatch);

    // Flip one base64 character inside the checksum's own quantum (the
    // envelope is 85 bytes: body 0..80, checksum 81..84 -> base64 chars
    // 108..111 carry the checksum): the checksum field itself changes.
    std::string bad_cksum = good;
    ASSERT_GT(bad_cksum.size(), 112u);
    bad_cksum[110] = (bad_cksum[110] == 'A') ? 'B' : 'A';
    const auto r = vx::crypto::import_pq_key(bad_cksum);
    EXPECT_EQ(r.error, KeyImportError::ChecksumMismatch)
        << vx::crypto::key_import_error_str(r.error);
}

TEST(VortexKeyImportTest, RejectsAddressMismatch) {
    // The load-bearing reject: key A's secret with key B's address and a
    // VALID checksum for that combination. Every structural layer passes;
    // the derivation check must refuse it - an import that claims an
    // address the key does not own protects nobody.
    const auto sk_a = test_sk(8);
    const auto sk_b = test_sk(9);
    const auto addr_b = address_of(sk_b);
    const std::string enc = encode(sk_a, addr_b); // valid checksum, wrong pairing
    const auto r = vx::crypto::import_pq_key(enc);
    EXPECT_EQ(r.error, KeyImportError::AddressMismatch) << vx::crypto::key_import_error_str(r.error);

    // And the honest pairing of key B still imports.
    const auto ok = vx::crypto::import_pq_key(encode(sk_b, addr_b));
    EXPECT_EQ(ok.error, KeyImportError::Ok);
}

TEST(VortexKeyImportTest, DerivePqAddressIsRootDeterministic) {
    const auto sk = test_sk(10);
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(sk);
    const auto root = vx::crypto::pq::xmss_root(sk, pub_seed);
    const auto a1 = vx::crypto::derive_pq_address(root);
    const auto a2 = vx::crypto::derive_pq_address(root);
    EXPECT_EQ(a1, a2);
    // A different key derives a different address.
    const auto other = vx::crypto::derive_pq_address(
        vx::crypto::pq::xmss_root(test_sk(11), vx::crypto::pq::pub_seed_from_sk(test_sk(11))));
    EXPECT_NE(a1, other);
}
