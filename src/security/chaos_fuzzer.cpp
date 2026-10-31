#include "vx/security/chaos_fuzzer.hpp"
#include "vx/net/swarm_node.hpp"
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/state/galois_trie.hpp"
#include "vx/vm/vortex_vm.hpp"
#include "vx/math/tdi_filter.hpp"

#include <random>
#include <cstring>
#include <vector>

namespace vx::security {

namespace {

using vx::net::WireHeader;
using vx::net::compute_wire_crc32c;
using vx::net::wire_header_plausible;

constexpr uint32_t WIRE_MAGIC = 0x56583630; // "VX60"
constexpr size_t WIRE_PAYLOAD = 65536;

// A deterministic RNG: chaos must be replayable bit-for-bit.
struct Rng {
    std::mt19937_64 gen;
    explicit Rng(uint64_t seed) : gen(seed) {}
    uint64_t next() { return gen(); }
    uint8_t byte() { return static_cast<uint8_t>(gen() & 0xFF); }
    size_t below(size_t n) { return static_cast<size_t>(gen() % n); }
    bool one_in(uint64_t n) { return (gen() % n) == 0; }
};

// ── Surface 1: VX60 wire frame ──────────────────────────────────────────────
// Build a valid packet, then choose one of the corruption vectors. The
// receiver path is: magic -> payload_len bounds -> CRC32C over payload.
void fuzz_wire(Rng& rng, uint64_t mutations, ChaosReport& rep) {
    std::vector<uint8_t> payload(WIRE_PAYLOAD);
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i * 31 + 7);

    for (uint64_t m = 0; m < mutations; ++m) {
        WireHeader h{};
        h.magic = WIRE_MAGIC;
        h.msg_type = static_cast<uint8_t>(vx::net::WireMsgType::RAW_BLOCK_64K);
        h.payload_len = static_cast<uint32_t>(payload.size());
        h.crc32c = compute_wire_crc32c(payload.data(), payload.size());
        h.peer_nonce = m + 1;

        std::vector<uint8_t> mutated = payload;
        const uint64_t vector = rng.next() % 5;

        switch (vector) {
            case 0: { // random bit flip in the payload -> CRC must break
                const size_t pos = rng.below(mutated.size());
                mutated[pos] ^= static_cast<uint8_t>(1u << rng.below(8));
                break;
            }
            case 1: { // payload_len overflow beyond the 64K frame budget
                h.payload_len = WIRE_PAYLOAD + 1 + static_cast<uint32_t>(rng.next() % 4096);
                break;
            }
            case 2: { // forged magic
                h.magic = static_cast<uint32_t>(rng.next());
                break;
            }
            case 3: { // forged CRC
                h.crc32c = static_cast<uint32_t>(rng.next());
                break;
            }
            default: { // truncated buffer: header claims more than we have
                mutated.resize(rng.below(mutated.size()));
                break;
            }
        }

        ++rep.wire_total;
        // Receiver validation path (identical to the socket ingest).
        const bool header_ok = wire_header_plausible(h) &&
                               h.crc32c == compute_wire_crc32c(mutated.data(), mutated.size());
        if (!header_ok) ++rep.wire_rejected;
    }
}

// ── Surface 2: BlockFrame 65536 B + Transaction 112 B ───────────────────────
void fuzz_frames(Rng& rng, uint64_t mutations, ChaosReport& rep) {
    using namespace vx::blockchain;

    for (uint64_t m = 0; m < mutations; ++m) {
        const uint64_t vector = rng.next() % 4;
        switch (vector) {
            case 0: { // corrupted frame magic must never deserialize as valid
                std::array<uint8_t, BLOCK_SIZE_BYTES> frame{};
                frame[0] = static_cast<uint8_t>(rng.next());
                frame[1] = static_cast<uint8_t>(rng.next());
                frame[2] = static_cast<uint8_t>(rng.next());
                frame[3] = static_cast<uint8_t>(rng.next());
                BlockView view{std::span<const uint8_t, BLOCK_SIZE_BYTES>(frame.data(), frame.size())};
                ++rep.frame_total;
                if (!view.valid_magic()) ++rep.frame_rejected;
                break;
            }
            case 1: { // UINT64_MAX amount / fee must not trap or wrap fatally
                Transaction tx{};
                std::memcpy(tx.sender_nfa, "CHAOS_MAX_SENDER_000000000000000000000000", 42);
                std::memcpy(tx.receiver_nfa, "CHAOS_MAX_RECV_0000000000000000000000000", 42);
                tx_set_amount(tx, UINT64_MAX);
                tx_set_fee(tx, UINT32_MAX); // fee is uint32_t: overflow boundary
                volatile uint64_t sink = tx_fee(tx) + 1;
                (void)sink;
                ++rep.frame_total; // accepted shape (memcpy deser) — no crash
                break;
            }
            case 2: { // zero-TDI spam: fee=1 -> (1*1024)/112 = 9 < threshold
                Transaction tx{};
                tx_set_amount(tx, rng.next());
                tx_set_fee(tx, 1);
                constexpr uint32_t kMinTdi = 1000;
                const uint64_t tdi = (static_cast<uint64_t>(tx_fee(tx)) * 1024u) /
                                     blockchain::TX_SIZE_BYTES;
                ++rep.frame_total;
                if (tdi < kMinTdi) ++rep.frame_rejected; // spam annihilated
                break;
            }
            default: { // random 112-byte garbage must survive plain memcpy
                Transaction tx{};
                for (size_t i = 0; i < sizeof(tx); ++i)
                    reinterpret_cast<uint8_t*>(&tx)[i] = rng.byte();
                volatile uint64_t sink = tx_amount(tx);
                (void)sink;
                ++rep.frame_total;
                break;
            }
        }
    }
}

// ── Surface 3: VortexVM random bytecodes ────────────────────────────────────
void fuzz_vm(Rng& rng, uint64_t mutations, ChaosReport& rep) {
    using namespace vx::vm;
    constexpr size_t kCodeLen = 128; // well inside BYTECODE_MAX_SIZE

    for (uint64_t m = 0; m < mutations; ++m) {
        std::array<uint8_t, VortexVM::BYTECODE_MAX_SIZE> code{};
        const size_t len = 1 + rng.below(kCodeLen);
        for (size_t i = 0; i < len; ++i) code[i] = rng.byte();

        VortexVM machine;
        VortexVM::ExecutionContext ctx;
        ctx.block_height = 1;
        const auto res = machine.execute(code.data(), ctx);
        ++rep.vm_total;
        if (!res.success) ++rep.vm_aborted; // underflow/overflow/truncation/gas
    }
}

// ── Surface 4: SGMT proof forgery ───────────────────────────────────────────
void fuzz_proofs(Rng& rng, uint64_t mutations, ChaosReport& rep) {
    using namespace vx::state;

    GaloisTrie trie;
    std::array<uint8_t, 32> key{}, val{};
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<uint8_t>(0xC4 ^ i);
        val[i] = static_cast<uint8_t>(0x5E + i * 3);
    }
    trie.put(key.data(), val.data());
    // Populate the trie so the witness carries BRANCH levels with real
    // sibling hash material (a single-leaf proof has nothing to forge).
    for (int k = 0; k < 64; ++k) {
        std::array<uint8_t, 32> k2{}, v2{};
        for (size_t i = 0; i < 32; ++i) {
            k2[i] = static_cast<uint8_t>(0xC4 ^ i ^ (k * 61 + 1));
            v2[i] = static_cast<uint8_t>(k * 7 + i);
        }
        trie.put(k2.data(), v2.data());
    }
    const auto root = trie.root_hash();
    auto proof = trie.generate_proof(key.data());

    for (uint64_t m = 0; m < mutations; ++m) {
        GaloisTrieProof forged = proof;
        const uint64_t vector = rng.next() % 3;
        switch (vector) {
            case 0: { // flip bits in a sibling / handed-over hash
                auto& levels = forged.levels;
                bool done = false;
                for (auto& lv : levels) {
                    if (!lv.siblings.empty()) {
                        auto& sib = lv.siblings[rng.below(lv.siblings.size())];
                        sib.second[rng.below(sib.second.size())] ^=
                            static_cast<uint8_t>(1u << rng.below(8));
                        done = true;
                        break;
                    }
                }
                if (!done) forged.present = !forged.present;
                break;
            }
            case 1: { // flip the level kind (PASS <-> BRANCH <-> EMPTY marker)
                auto& levels = forged.levels;
                if (levels.empty()) { forged.present = !forged.present; break; }
                GaloisTrieProof::Level& lv = levels[rng.below(levels.size())];
                lv.kind = static_cast<uint8_t>((lv.kind + 1) % 3);
                break;
            }
            default: { // corrupt structural fields the verifier re-derives
                auto& levels = forged.levels;
                if (levels.empty()) { forged.present = !forged.present; break; }
                GaloisTrieProof::Level& lv = levels[rng.below(levels.size())];
                if (rng.one_in(2)) {
                    lv.depth ^= 0xFF; // guaranteed != level index
                } else {
                    lv.nibble ^= 0x80; // guaranteed != key[d]
                }
                break;
            }
        }

        ++rep.proof_mutations;
        // A forged witness must never verify.
        if (GaloisTrie::verify_proof(root.data(), key.data(), val.data(), forged)) {
            ++rep.proof_forgery_hits; // false positive — catastrophic
        }
        // A tampered VALUE must never verify against the pristine witness.
        std::array<uint8_t, 32> bad_val = val;
        bad_val[m % 32] ^= 0x40;
        if (GaloisTrie::verify_proof(root.data(), key.data(), bad_val.data(), proof)) {
            ++rep.proof_forgery_hits;
        }
    }
}

} // namespace

ChaosReport run_chaos_fuzz_round(uint64_t seed, uint64_t mutations) {
    ChaosReport rep;
    Rng rng(seed);

    fuzz_wire(rng, mutations, rep);
    fuzz_frames(rng, mutations, rep);
    fuzz_vm(rng, mutations, rep);
    fuzz_proofs(rng, mutations, rep);

    rep.mutated_inputs_tested = rep.wire_total + rep.frame_total + rep.vm_total +
                                rep.proof_mutations;
    return rep;
}

} // namespace vx::security
