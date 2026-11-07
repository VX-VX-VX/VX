// VortexWitnessDeliveryTest - BACKLOG 2.11 stage 2: the witness-set
// delivery protocol around the VXC7 witness_merkle_root commitment.
//
// What is enforced, and where:
//   - HttpServer::apply_remote_frame PARKS a tip-extending frame whose
//     canonical witness set has not arrived (MISSING_WITNESS) instead of
//     refusing it: witnesses travel out-of-band and normally trail the
//     frame by one gossip hop;
//   - a frame whose header commitment matches NO canonical rule
//     (MISMATCH) is refused outright and counted against the sending
//     peer - withholding becomes attributable;
//   - the SwarmNode witness callback retries a parked frame through the
//     SAME apply path when its witness arrives (no bypass surface);
//   - the park is bounded (32 frames, oldest evicted) and every parked
//     frame expires after the park TTL;
//   - a parked frame whose tip has moved on is dead and is dropped on
//     retry, never applied out of order.

#include <gtest/gtest.h>
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/rpc/http_server.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"

#include <cstring>
#include <ctime>
#include <filesystem>
#include <memory>
#include <thread>
#include <unistd.h>

using namespace vx::blockchain;
using vx::core::U128;

namespace {

std::string temp_dir(const char *tag) {
    auto dir = std::filesystem::temp_directory_path() /
               (std::string(tag) + "_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    return dir.string();
}

Address addr_of(const std::string &s) {
    Address a{};
    std::memcpy(a.data(), s.data(), s.size() < 42 ? s.size() : 42);
    return a;
}

struct PqAccount {
    std::array<uint8_t, 32> sk{};
    std::array<uint8_t, 32> root{};
    Address addr{};
};

PqAccount make_pq_account(const char *tag) {
    PqAccount acc;
    VortexSponge256::compute(reinterpret_cast<const uint8_t *>(tag), std::strlen(tag),
                             acc.sk.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(acc.sk);
    acc.root = vx::crypto::pq::xmss_root(acc.sk, pub_seed);
    derive_pq_address(acc.root.data(), acc.addr.data());
    return acc;
}

Transaction make_tx(const Address &sender, const Address &receiver, uint64_t amount,
                    uint32_t nonce) {
    Transaction tx{};
    std::memcpy(tx.sender_nfa, sender.data(), 42);
    std::memcpy(tx.receiver_nfa, receiver.data(), 42);
    tx_set_amount(tx, amount);
    tx_set_fee(tx, 100);
    tx_set_nonce(tx, nonce);
    return tx;
}

BlockBuilder next_block(vx::storage::BlockStore &store, uint64_t ts) {
    BlockBuilder b;
    b.set_height(store.chain_height());
    b.set_timestamp(ts);
    uint8_t tip[32];
    store.tip_hash(tip);
    b.set_prev_hash(tip);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    return b;
}

BlockFrame sealed_frame(vx::storage::BlockStore &store, BlockBuilder &b) {
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    EXPECT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
    return f;
}

// The full setup: genesis replayed, the height-1 protocol mint applied,
// the demo spender funded, and an HttpServer wired over the same store +
// ledger (port 0: the RPC listener is never started - only the intake
// path and its parking logic are under test).
struct DeliveryChain {
    std::string dir;
    std::unique_ptr<vx::storage::BlockStore> store;
    std::unique_ptr<vx::state::LedgerState> ledger;
    std::unique_ptr<vx::rpc::HttpServer> server;
    PqAccount demo{};
    Address spender{};

    explicit DeliveryChain(const char *tag) : dir(temp_dir(tag)) {
        store = std::make_unique<vx::storage::BlockStore>(dir + "/ledger.vxb", "genesis.bin", 8);
        ledger = std::make_unique<vx::state::LedgerState>();
        const auto *g = store->get_block(0);
        if (!g) {
            ADD_FAILURE();
            return;
        }
        BlockFrame gf;
        std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
        if (!ledger->apply_block(BlockView(gf)).ok) {
            ADD_FAILURE();
            return;
        }

        demo = make_pq_account("VX_DEMO_SPENDER_SK_V1");
        spender = genesis2_mint_receiver_payload();

        BlockBuilder b = next_block(*store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction mint = make_tx(addr_of("GENESIS_2"), spender, GENESIS_2_MINT_ATOMICS, 0);
        sign_transaction(mint); // system sender: structural digest only
        if (!b.add_transaction(mint)) {
            ADD_FAILURE();
            return;
        }
        const BlockFrame f = sealed_frame(*store, b);
        if (!store->append_block(f)) {
            ADD_FAILURE();
            return;
        }
        if (!ledger->apply_block(BlockView(f)).ok) {
            ADD_FAILURE();
            return;
        }
        if (!(ledger->balance_of(spender) == U128(GENESIS_2_MINT_ATOMICS))) {
            ADD_FAILURE();
            return;
        }

        server = std::make_unique<vx::rpc::HttpServer>(*store, *ledger, 0, dir);
    }

    ~DeliveryChain() {
        std::filesystem::remove_all(dir);
    }

    // The ledger's binding oracle, as the production verifiers pass it.
    BoundRootOf oracle() {
        vx::state::LedgerState *l = ledger.get();
        return [l](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
            return l->pq_root_of(a, out);
        };
    }
};

// Builds an honest tip-extending frame spending from the demo spender:
// signed (witness registered), canonically bound, sealed. out_witness (when
// non-null) receives the witness so a test can simulate the WIRE arrival of
// the same (digest, sender, witness) triple after the registry was cleared
// - re-signing an already-signed tx is NOT digest-stable (the SegPQ anchor
// depends on the signed bytes), so the wire shape is the honest simulation.
BlockFrame honest_spend_frame(DeliveryChain &c, const char *sink_tag, uint32_t nonce,
                              uint64_t amount,
                              vx::crypto::pq::PqSignatureWitness *out_witness = nullptr) {
    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t = make_tx(c.spender, addr_of(sink_tag), amount, nonce);
    if (!vx::crypto::pq::pq_sign_transaction(t, c.demo.sk, nullptr, nullptr, out_witness)) {
        ADD_FAILURE();
        return BlockFrame{};
    }
    if (!b.add_transaction(t)) {
        ADD_FAILURE();
        return BlockFrame{};
    }
    if (b.bind_canonical_witnesses(c.oracle()) != 1u) {
        ADD_FAILURE();
        return BlockFrame{};
    }
    return sealed_frame(*c.store, b);
}

// Registers a witness exactly the way a PQ_WITNESS wire message does:
// digest + sender + witness, no transaction bytes involved.
void wire_arrive(const BlockFrame &f, uint32_t tx_index,
                 const vx::crypto::pq::PqSignatureWitness &w) {
    const auto *raw = reinterpret_cast<const RawBlock *>(f.data());
    std::array<uint8_t, 32> d = vx::crypto::pq::tx_msg_digest(raw->transactions[tx_index]);
    EXPECT_TRUE(vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
        d, raw->transactions[tx_index].sender_nfa, w));
}

std::array<uint8_t, 32> first_user_tx_digest(const BlockFrame &f) {
    const auto *raw = reinterpret_cast<const RawBlock *>(f.data());
    EXPECT_GE(raw->header.tx_count, 1u);
    return vx::crypto::pq::tx_msg_digest(raw->transactions[0]);
}

} // namespace

// -- A tip-extending frame whose witnesses have not arrived is PARKED:
// the store height is unchanged, nothing is applied, and the frame is
// retried (and applied) when its witness arrives.
TEST(VortexWitnessDeliveryTest, MissingWitnessParksThenRetries) {
    DeliveryChain c("vx_wd_park");
    ASSERT_TRUE(c.server != nullptr);

    vx::crypto::pq::PqSignatureWitness w{};
    const BlockFrame f =
        honest_spend_frame(c, "NFA_WD_SINK_A_000000000000000000000000", 0, 1000000000u, &w);
    const auto digest = first_user_tx_digest(f);
    const uint64_t height_before = c.store->chain_height();

    // Witnesses-in-flight window: the registry is emptied AFTER the frame
    // was built (the cache is never an authority).
    vx::crypto::pq::PqWitnessRegistry::instance().clear_witnesses_for_test();
    EXPECT_EQ(WitnessRootStatus::MISSING_WITNESS,
              verify_witness_merkle(*reinterpret_cast<const RawBlock *>(f.data()), c.oracle()));
    EXPECT_FALSE(c.server->apply_remote_frame(f.data()));
    EXPECT_EQ(c.store->chain_height(), height_before) << "a parked frame must not move the tip";
    EXPECT_EQ(c.server->parked_witness_count(), 1u);

    // The witness arrives over the wire (the same digest + sender + witness
    // triple the proposer broadcast); the retry seam fires and the frame
    // applies through the SAME apply path.
    wire_arrive(f, 0, w);
    c.server->on_witness_arrived(digest);
    EXPECT_EQ(c.store->chain_height(), height_before + 1)
        << "the parked frame must apply once its witness arrived";
    EXPECT_EQ(c.server->parked_witness_count(), 0u);
}

// -- A frame whose header commitment matches NO canonical rule
// (MISMATCH) is refused outright, is NOT parked, and is counted against
// the sending peer: withholding becomes attributable.
TEST(VortexWitnessDeliveryTest, MismatchRefusedAndAttributed) {
    DeliveryChain c("vx_wd_mismatch");
    ASSERT_TRUE(c.server != nullptr);

    BlockFrame f = honest_spend_frame(c, "NFA_WD_SINK_B_000000000000000000000000", 0, 1000000000u);
    auto *raw = reinterpret_cast<RawBlock *>(f.data());
    raw->header.witness_merkle_root[3] ^= 0x40;
    const uint64_t height_before = c.store->chain_height();

    EXPECT_FALSE(c.server->apply_remote_frame(f.data()));
    EXPECT_EQ(c.store->chain_height(), height_before);
    EXPECT_EQ(c.server->parked_witness_count(), 0u)
        << "a MISMATCH frame is a lie, not a lag - it must not park";
    EXPECT_EQ(c.server->witness_withhold_count("wire"), 1u);
    EXPECT_EQ(c.server->witness_withhold_count("other-peer"), 0u);
}

// -- The park is bounded: the oldest parked frame is evicted when the
// cap is hit, so a peer cannot make the node buffer unbounded witness
// traffic.
TEST(VortexWitnessDeliveryTest, ParkSetIsBounded) {
    DeliveryChain c("vx_wd_cap");
    ASSERT_TRUE(c.server != nullptr);

    const BlockFrame f =
        honest_spend_frame(c, "NFA_WD_SINK_C_000000000000000000000000", 0, 1000000000u);
    vx::crypto::pq::PqWitnessRegistry::instance().clear_witnesses_for_test();
    for (int i = 0; i < 40; ++i) {
        EXPECT_FALSE(c.server->apply_remote_frame(f.data()));
    }
    EXPECT_EQ(c.server->parked_witness_count(), 32u)
        << "the park must evict the oldest, never grow past 32";
}

// -- Every parked frame expires after the park TTL: the witnesses-in-
// flight window is finite on both ends (arrival or expiry).
TEST(VortexWitnessDeliveryTest, ParkedFramesExpire) {
    DeliveryChain c("vx_wd_ttl");
    ASSERT_TRUE(c.server != nullptr);
    c.server->set_witness_park_ttl_for_test(std::chrono::milliseconds(50));

    const BlockFrame f =
        honest_spend_frame(c, "NFA_WD_SINK_D_000000000000000000000000", 0, 1000000000u);
    vx::crypto::pq::PqWitnessRegistry::instance().clear_witnesses_for_test();
    EXPECT_FALSE(c.server->apply_remote_frame(f.data()));
    EXPECT_EQ(c.server->parked_witness_count(), 1u);

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    // Any subsequent intake attempt purges the expired frame lazily.
    EXPECT_FALSE(c.server->apply_remote_frame(f.data()));
    EXPECT_EQ(c.server->parked_witness_count(), 1u)
        << "the expired frame is dropped and the SAME frame re-parks as a "
           "fresh entry - the park never accumulates past one live attempt";
}

// -- A parked frame whose tip has moved on is dead: the retry refuses it
// (the tip check inside the shared apply path) and the park drains.
TEST(VortexWitnessDeliveryTest, TipMovedKillsParkedFrame) {
    DeliveryChain c("vx_wd_tipmove");
    ASSERT_TRUE(c.server != nullptr);

    // Both frames are built while the registry is intact: signing
    // registers the witness and the canonical binding needs it.
    vx::crypto::pq::PqSignatureWitness stale_w{};
    vx::crypto::pq::PqSignatureWitness winner_w{};
    const BlockFrame stale =
        honest_spend_frame(c, "NFA_WD_SINK_E_000000000000000000000000", 0, 1000000000u, &stale_w);
    const BlockFrame winner =
        honest_spend_frame(c, "NFA_WD_SINK_F_000000000000000000000000", 0, 2000000000u, &winner_w);
    const auto stale_digest = first_user_tx_digest(stale);

    // Park the stale frame (witnesses cleared -> MISSING).
    vx::crypto::pq::PqWitnessRegistry::instance().clear_witnesses_for_test();
    EXPECT_FALSE(c.server->apply_remote_frame(stale.data()));
    EXPECT_EQ(c.server->parked_witness_count(), 1u);

    // The competing frame at the same height WINS: its witness arrives
    // over the wire, the live path applies the frame and the tip moves
    // past the parked one.
    wire_arrive(winner, 0, winner_w);
    EXPECT_TRUE(c.server->apply_remote_frame(winner.data()));
    const uint64_t h_after_winner = c.store->chain_height();

    // The stale frame's witness arrives late: the retry hits the tip
    // check and the dead frame is dropped, never applied out of order.
    wire_arrive(stale, 0, stale_w);
    c.server->on_witness_arrived(stale_digest);
    EXPECT_EQ(c.server->parked_witness_count(), 0u);
    EXPECT_EQ(c.store->chain_height(), h_after_winner)
        << "a tip-stale parked frame must never resurrect";
}

// -- A witness for an UNRELATED transaction does not retry the parked
// frame: only the digests the parked frame actually carries trigger it.
TEST(VortexWitnessDeliveryTest, UnrelatedWitnessDoesNotRetry) {
    DeliveryChain c("vx_wd_unrelated");
    ASSERT_TRUE(c.server != nullptr);

    const BlockFrame f =
        honest_spend_frame(c, "NFA_WD_SINK_G_000000000000000000000000", 0, 1000000000u);
    vx::crypto::pq::PqWitnessRegistry::instance().clear_witnesses_for_test();
    EXPECT_FALSE(c.server->apply_remote_frame(f.data()));
    EXPECT_EQ(c.server->parked_witness_count(), 1u);

    // A witness for an unrelated digest arrives over the wire.
    Transaction other =
        make_tx(c.spender, addr_of("NFA_WD_SINK_H_000000000000000000000000"), 12345u, 7);
    vx::crypto::pq::PqSignatureWitness other_w{};
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(other, c.demo.sk, nullptr, nullptr, &other_w));
    c.server->on_witness_arrived(vx::crypto::pq::tx_msg_digest(other));
    EXPECT_EQ(c.server->parked_witness_count(), 1u)
        << "an unrelated witness must not touch the parked frame";
}
