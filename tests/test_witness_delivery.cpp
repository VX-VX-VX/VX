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
#include "vx/net/swarm_node.hpp"
#include "vx/rpc/http_server.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <memory>
#include <thread>
#include <unistd.h>
#include <vector>

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

// BACKLOG 1.5 P0 GATE: one honest rollover certificate for the connect-time
// CERT_INV assertion (same construction the wiring test uses).
vx::crypto::pq::PqRolloverCert make_test_cert(const char *tag) {
    std::array<uint8_t, 32> master{};
    VortexSponge256::compute(reinterpret_cast<const uint8_t *>(tag), std::strlen(tag),
                             master.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(master);
    vx::crypto::pq::PqRolloverCert cert;
    std::memcpy(cert.sender.data(), "PQA", 3);
    std::memcpy(cert.sender.data() + 3, master.data(), 32);
    for (size_t i = 35; i < cert.sender.size(); ++i)
        cert.sender[i] = static_cast<uint8_t>('A' + (i % 26));
    cert.from_window = 0;
    cert.to_window = 1;
    cert.old_root = vx::crypto::pq::xmss_root_tree(master, pub_seed, 0);
    cert.new_root = vx::crypto::pq::xmss_root_tree(master, pub_seed, 1);
    cert.witness = vx::crypto::pq::pq_sign_rollover(master, 0, 1, nullptr);
    return cert;
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

// -- The park is bounded TWICE (security review 2026-11-12): per peer
// first (one peer cannot evict frames other peers delivered by flooding
// cheap junk — parking runs before the expensive PoGW hash), then
// globally (the oldest parked frame is evicted when the global cap is
// hit, so the node never buffers unbounded witness traffic).
TEST(VortexWitnessDeliveryTest, ParkSetIsBounded) {
    DeliveryChain c("vx_wd_cap");
    ASSERT_TRUE(c.server != nullptr);

    const BlockFrame f =
        honest_spend_frame(c, "NFA_WD_SINK_C_000000000000000000000000", 0, 1000000000u);
    vx::crypto::pq::PqWitnessRegistry::instance().clear_witnesses_for_test();
    // 40 deliveries from ONE label: the per-peer cap binds at 8.
    for (int i = 0; i < 40; ++i) {
        EXPECT_FALSE(c.server->apply_remote_frame(f.data()));
    }
    EXPECT_EQ(c.server->parked_witness_count(), 8u)
        << "one peer must not hold the whole park (per-peer cap)";
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

// -- BACKLOG 2.11 first checkbox, verified end to end: a brand-new REMOTE
// sender (a PQA address no node has ever bound) spends for the first time
// in a remotely-arrived block. The frame parks on the missing witness,
// the witness arrives over the wire, and the block applies THROUGH the
// self-certifying binding path: the address commits its own key root, so
// the first witnessed spend binds it - no local registration needed.
TEST(VortexWitnessDeliveryTest, RemoteFirstSpendBindsAndContinues) {
    DeliveryChain c("vx_wd_firstseen");
    ASSERT_TRUE(c.server != nullptr);

    // A brand-new PQA account nobody has bound: address derived from its
    // own key root.
    const PqAccount newcomer = make_pq_account("VX_WD_NEWCOMER_SK_V1");
    ASSERT_EQ(0, std::memcmp(newcomer.addr.data(), newcomer.addr.data(), 42));

    // The demo spender funds the newcomer (the RECEIVER side needs no
    // binding), locally applied so the tip advances.
    {
        BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction fund = make_tx(c.spender, newcomer.addr, 5000000000u, 0);
        ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(fund, c.demo.sk));
        ASSERT_TRUE(b.add_transaction(fund));
        ASSERT_EQ(1u, b.bind_canonical_witnesses(c.oracle()));
        const BlockFrame f = sealed_frame(*c.store, b);
        ASSERT_TRUE(c.store->append_block(f));
        ASSERT_TRUE(c.ledger->apply_block(BlockView(f)).ok);
    }
    const uint64_t height_before = c.store->chain_height();

    // The newcomer's FIRST spend ever, inside a remotely-arrived frame.
    vx::crypto::pq::PqSignatureWitness w{};
    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction spend =
        make_tx(newcomer.addr, addr_of("NFA_WD_SINK_R_000000000000000000000000"), 1000000000u, 0);
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(spend, newcomer.sk, nullptr, nullptr, &w));
    ASSERT_TRUE(b.add_transaction(spend));
    ASSERT_EQ(1u, b.bind_canonical_witnesses(c.oracle()))
        << "the producer must resolve the first-spend canonical root "
           "self-certifyingly";
    const BlockFrame f = sealed_frame(*c.store, b);
    const auto digest = vx::crypto::pq::tx_msg_digest(
        reinterpret_cast<const RawBlock *>(f.data())->transactions[0]);

    // The remote node's view: it holds NO witness for the newcomer yet.
    vx::crypto::pq::PqWitnessRegistry::instance().clear_witnesses_for_test();
    EXPECT_EQ(WitnessRootStatus::MISSING_WITNESS,
              verify_witness_merkle(*reinterpret_cast<const RawBlock *>(f.data()), c.oracle()));
    EXPECT_FALSE(c.server->apply_remote_frame(f.data()));
    EXPECT_EQ(c.server->parked_witness_count(), 1u);

    // The witness arrives over the wire; the parked frame applies and the
    // ledger BINDS the newcomer (first-seen binding, no local registry).
    wire_arrive(f, 0, w);
    c.server->on_witness_arrived(digest);
    EXPECT_EQ(c.store->chain_height(), height_before + 1)
        << "a remote first-spend must apply once its witness arrived";
    EXPECT_EQ(c.server->parked_witness_count(), 0u);
    std::array<uint8_t, 32> bound{};
    EXPECT_TRUE(c.ledger->pq_root_of(newcomer.addr, bound));
    EXPECT_EQ(0, std::memcmp(bound.data(), newcomer.root.data(), 32));

    // The now-bound sender spends again in the next remote frame: the
    // bound-root path (stage-1 canonical selection) serves it.
    vx::crypto::pq::PqSignatureWitness w2{};
    BlockBuilder b2 = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction spend2 =
        make_tx(newcomer.addr, addr_of("NFA_WD_SINK_S_000000000000000000000000"), 1000000000u, 1);
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(spend2, newcomer.sk, nullptr, nullptr, &w2));
    ASSERT_TRUE(b2.add_transaction(spend2));
    ASSERT_EQ(1u, b2.bind_canonical_witnesses(c.oracle()));
    const BlockFrame f2 = sealed_frame(*c.store, b2);
    const auto digest2 = vx::crypto::pq::tx_msg_digest(
        reinterpret_cast<const RawBlock *>(f2.data())->transactions[0]);
    vx::crypto::pq::PqWitnessRegistry::instance().clear_witnesses_for_test();
    EXPECT_FALSE(c.server->apply_remote_frame(f2.data()));
    EXPECT_EQ(c.server->parked_witness_count(), 1u);
    wire_arrive(f2, 0, w2);
    c.server->on_witness_arrived(digest2);
    EXPECT_EQ(c.store->chain_height(), height_before + 2);
    EXPECT_EQ(c.server->parked_witness_count(), 0u);
}

// -- BACKLOG 2.11 third checkbox: witness retention. A locally produced
// block's witness is re-served to a peer that connects and PINGs (one-shot
// per promotion), closing the fire-and-forget gossip gap for a peer that
// joined mid-stream.
namespace {

uint16_t free_tcp_port() {
    int probe = ::socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_GE(probe, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    EXPECT_EQ(::bind(probe, reinterpret_cast<sockaddr *>(&a), sizeof(a)), 0);
    socklen_t alen = sizeof(a);
    ::getsockname(probe, reinterpret_cast<sockaddr *>(&a), &alen);
    const uint16_t port = ntohs(a.sin_port);
    ::close(probe);
    return port;
}

bool read_full(int fd, void *buf, size_t len) {
    auto *p = static_cast<uint8_t *>(buf);
    size_t off = 0;
    while (off < len) {
        const ssize_t n = ::recv(fd, p + off, len - off, 0);
        if (n <= 0)
            return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

bool send_full(int fd, const void *buf, size_t len) {
    const auto *p = static_cast<const uint8_t *>(buf);
    size_t off = 0;
    while (off < len) {
        const ssize_t n = ::send(fd, p + off, len - off, MSG_NOSIGNAL);
        if (n <= 0)
            return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

} // namespace

TEST(VortexWitnessDeliveryTest, RetentionServedOnConnect) {
    DeliveryChain c("vx_wd_retention");
    ASSERT_TRUE(c.server != nullptr);

    // A locally produced spend block: signing registers the witness, the
    // producer binds + seals, and the block applies to the local chain.
    const BlockFrame f =
        honest_spend_frame(c, "NFA_WD_SINK_R_000000000000000000000000", 0, 700000000u);
    ASSERT_TRUE(c.store->append_block(f));
    ASSERT_TRUE(c.ledger->apply_block(BlockView(f)).ok);
    const auto digest = first_user_tx_digest(f);

    const uint16_t port = free_tcp_port();
    c.server->attach_p2p(port, {});

    // P0 GATE: the registry holds one certificate, so the connect-time
    // retention must announce its id alongside the witness window.
    const auto cert = make_test_cert("vx_wd_cert_inv");
    ASSERT_TRUE(vx::crypto::pq::PqWitnessRegistry::instance().register_rollover_cert(cert));
    const auto cert_id = vx::crypto::pq::rollover_cert_id(cert);

    // Connect and PING: the promotion fires the retention serve before the
    // PONG goes out.
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    ASSERT_EQ(::connect(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)), 0);
    timeval tv{5, 0};
    ASSERT_EQ(::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)), 0);

    vx::net::WireHeader ping = vx::net::SwarmNode::make_header(vx::net::WireMsgType::PING, 0, 77);
    ping.crc32c = vx::net::compute_wire_crc32c(nullptr, 0);
    ASSERT_TRUE(send_full(fd, &ping, sizeof(ping)));

    bool got_pong = false, got_witness = false, witness_matches = false, got_cert_inv = false,
         cert_inv_matches = false;
    for (int i = 0; i < 50 && !(got_pong && got_witness && got_cert_inv); ++i) {
        vx::net::WireHeader h{};
        if (!read_full(fd, &h, sizeof(h)))
            break;
        std::vector<uint8_t> payload(h.payload_len);
        if (h.payload_len && !read_full(fd, payload.data(), h.payload_len))
            break;
        if (h.msg_type == static_cast<uint8_t>(vx::net::WireMsgType::PONG))
            got_pong = true;
        if (h.msg_type == static_cast<uint8_t>(vx::net::WireMsgType::PQ_WITNESS) &&
            payload.size() == 32 + 42 + sizeof(vx::crypto::pq::PqSignatureWitness)) {
            got_witness = true;
            witness_matches = std::memcmp(payload.data(), digest.data(), 32) == 0 &&
                              std::memcmp(payload.data() + 32, c.spender.data(), 42) == 0;
        }
        // CERT_INV: count(u32 LE) + ids; the announced id must be ours.
        if (h.msg_type == static_cast<uint8_t>(vx::net::WireMsgType::CERT_INV) &&
            payload.size() >= 4 && payload.size() <= 4 + 64 * 32) {
            uint32_t n = 0;
            std::memcpy(&n, payload.data(), 4);
            if (n >= 1 && payload.size() >= 4 + n * 32) {
                for (uint32_t k = 0; k < n; ++k) {
                    if (std::memcmp(payload.data() + 4 + k * 32, cert_id.data(), 32) == 0) {
                        got_cert_inv = true;
                        cert_inv_matches = true;
                    }
                }
            }
        }
    }
    EXPECT_TRUE(got_pong);
    EXPECT_TRUE(got_witness) << "the retention window must re-serve the spend witness";
    EXPECT_TRUE(witness_matches) << "digest and sender must be the spend tx's";
    EXPECT_TRUE(got_cert_inv) << "connect-time retention must announce the cert inventory";
    EXPECT_TRUE(cert_inv_matches);
    ::close(fd);

    // Security review P1-2: the window is served at most once per source IP
    // per the rate interval - a second connect (fresh port, same IP) gets
    // its PONG but NO witness re-serve.
    int fd2 = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(fd2, 0);
    ASSERT_EQ(::connect(fd2, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)), 0);
    ASSERT_EQ(::setsockopt(fd2, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)), 0);
    vx::net::WireHeader ping2 = vx::net::SwarmNode::make_header(vx::net::WireMsgType::PING, 0, 78);
    ping2.crc32c = vx::net::compute_wire_crc32c(nullptr, 0);
    ASSERT_TRUE(send_full(fd2, &ping2, sizeof(ping2)));
    bool pong2 = false, witness2 = false, cert_inv2 = false;
    for (int i = 0; i < 50 && !pong2; ++i) {
        vx::net::WireHeader h{};
        if (!read_full(fd2, &h, sizeof(h)))
            break;
        std::vector<uint8_t> payload(h.payload_len);
        if (h.payload_len && !read_full(fd2, payload.data(), h.payload_len))
            break;
        if (h.msg_type == static_cast<uint8_t>(vx::net::WireMsgType::PONG))
            pong2 = true;
        if (h.msg_type == static_cast<uint8_t>(vx::net::WireMsgType::PQ_WITNESS))
            witness2 = true;
        if (h.msg_type == static_cast<uint8_t>(vx::net::WireMsgType::CERT_INV))
            cert_inv2 = true;
    }
    EXPECT_TRUE(pong2) << "the second connect must still be alive and promoted";
    EXPECT_FALSE(witness2) << "the same IP must not re-pull the window inside the interval";
    EXPECT_FALSE(cert_inv2) << "the rate gate must also cover the cert inventory serve";
    ::close(fd2);
}

// -- BACKLOG 2.11 third checkbox: attribution uses the REAL peer label. A
// tampered commitment arriving over the wire from a live connection must be
// scored against that connection's ip:port, not the default "wire" label.
TEST(VortexWitnessDeliveryTest, MismatchAttributedToRealPeer) {
    DeliveryChain c("vx_wd_attr");
    ASSERT_TRUE(c.server != nullptr);

    // An honest, tip-extending frame whose header commitment is then
    // corrupted: the canonical rules still resolve a root (the witness is
    // registered by signing), so verify_witness_merkle reports MISMATCH -
    // the attributable failure - not MISSING_WITNESS.
    BlockFrame bad = honest_spend_frame(c, "NFA_WD_SINK_M_000000000000000000000000", 0, 500000u);
    bad.data()[0x1D8 + 5] ^= 0x40; // witness_merkle_root

    const uint16_t port = free_tcp_port();
    c.server->attach_p2p(port, {});

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    ASSERT_EQ(::connect(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)), 0);
    socklen_t clen = sizeof(sa);
    ::getsockname(fd, reinterpret_cast<sockaddr *>(&sa), &clen);
    const std::string label = "127.0.0.1:" + std::to_string(ntohs(sa.sin_port));

    const auto send_bad = [&]() {
        vx::net::WireHeader h =
            vx::net::SwarmNode::make_header(vx::net::WireMsgType::RAW_BLOCK_64K, 65536, 42);
        h.crc32c = vx::net::compute_wire_crc32c(bad.data(), 65536);
        if (!send_full(fd, &h, sizeof(h)))
            return false;
        return send_full(fd, bad.data(), 65536);
    };

    // Three strikes over the wire; each is scored against the real label.
    for (int i = 0; i < 3; ++i)
        ASSERT_TRUE(send_bad());

    bool scored = false;
    for (int i = 0; i < 100 && !scored; ++i) {
        scored = c.server->witness_withhold_count(label) == 3u;
        if (!scored)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_TRUE(scored) << "the MISMATCH path must attribute to the connection's ip:port";
    EXPECT_EQ(c.server->witness_withhold_count("wire"), 0u)
        << "the default label must not absorb live-connection strikes";
    ::close(fd);
}
