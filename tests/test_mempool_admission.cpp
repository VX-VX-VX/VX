// VortexMempoolAdmissionTest - BACKLOG 0.14 admission wiring (Stage D1).
//
// Pins the RPC -> mempool -> miner -> ledger call chain end to end, at the
// real integration seam the wiring lives in: HttpServer::route() (the same
// entry the HTTP worker threads and the RPC fuzz target use; no socket is
// bound, port 0, start() is never called).
//
//   1. MempoolSubmitVisibleInStats     - a valid signed transfer submitted
//      to /api/mempool/submit is visible in the mempool stats BEFORE any
//      seal, and no block is produced.
//   2. AdmissionRejectsSecondSameNonce - a second submit of the same
//      sender/nonce while the first is still pending is refused by the
//      mempool admission gate (pending-nonce reservation), not by the
//      request parser.
//   3. SealAppliesToLedger             - /api/mempool/seal runs the miner's
//      sealing flow once: the pending tx is sealed into a block, removed
//      from the mempool, and the ledger applies it (receiver credited,
//      sender debited amount + fee, nonce advanced).
//   4. TransferEndpointSealsThroughMempool - /api/transfer keeps its
//      response contract (status ok + block hash) and now admits through
//      the mempool: the tx is sealed by the miner's flow and applied.
//   5. UnwitnessedTransferRefused      - the keyless-transfer refusal still
//      precedes admission (no tx may enter the mempool without a PQ
//      witness).

#include <gtest/gtest.h>
#include "vx/rpc/http_server.hpp"
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/crypto/pq_signature.hpp"

#include <cstring>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <memory>
#include <string>
#include <unistd.h>

using namespace vx::blockchain;
using vx::core::U128;

namespace {

// Test-only token (never a real secret): presented by post() so the
// fail-closed RPC auth gate admits the stage_D seam endpoints.
constexpr char kTestToken[] = "vx-admission-test-token";

std::string temp_dir(const char* tag) {
    auto dir = std::filesystem::temp_directory_path() /
               (std::string(tag) + "_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    return dir.string();
}

Address payload_of(const std::string& nfa) { // strips the "NFA_V6_" prefix
    Address a{};
    std::memcpy(a.data(), nfa.data() + 7, 42);
    return a;
}

Address addr_of(const std::string& s) {
    Address a{};
    std::memcpy(a.data(), s.data(), s.size() < 42 ? s.size() : 42);
    return a;
}

std::string payload_string(const Address& a) {
    return std::string(reinterpret_cast<const char*>(a.data()), 42);
}

// A test account bound to a post-quantum WOTS+/XMSS key (same idiom as
// test_documented_gaps.cpp).
struct PqAccount {
    std::array<uint8_t, 32> sk{};
    std::array<uint8_t, 32> root{};
    Address addr{};
};

PqAccount make_pq_account(const char* tag) {
    PqAccount acc;
    VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag),
                             std::strlen(tag), acc.sk.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(acc.sk);
    acc.root = vx::crypto::pq::xmss_root(acc.sk, pub_seed);
    derive_pq_address(acc.root.data(), acc.addr.data());
    return acc;
}

// Signs a transaction with the account's PQ key (registers the witness in
// the PqWitnessRegistry, exactly like a real client would) and returns the
// base64 witness body the RPC contract carries.
std::string pq_sign_b64(Transaction& tx, const PqAccount& acc) {
    if (!vx::crypto::pq::pq_sign_transaction(tx, acc.sk)) return "";
    const auto& w = [&] {
        vx::crypto::pq::PqSignatureWitness out{};
        // pq_sign_transaction registers the witness; fetch our copy from the
        // registry by digest so the bytes we encode are the registered ones.
        const auto digest = vx::crypto::pq::tx_msg_digest(tx);
        vx::crypto::pq::PqWitnessRegistry::instance().lookup(digest, out);
        return out;
    }();
    static constexpr char kB64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&w);
    const size_t n = sizeof(w);
    std::string out;
    out.reserve(((n + 2) / 3) * 4);
    for (size_t i = 0; i < n; i += 3) {
        const uint32_t b0 = p[i];
        const uint32_t b1 = (i + 1 < n) ? p[i + 1] : 0;
        const uint32_t b2 = (i + 2 < n) ? p[i + 2] : 0;
        out += kB64[(b0 >> 2) & 0x3F];
        out += kB64[((b0 << 4) | (b1 >> 4)) & 0x3F];
        out += kB64[((b1 << 2) | (b2 >> 6)) & 0x3F];
        out += kB64[b2 & 0x3F];
    }
    return out;
}

// Builds the canonical signed transfer for one admission round-trip.
std::string sign_transfer_b64(const Address& sender, const Address& receiver,
                              uint64_t amount, uint32_t fee, uint32_t nonce,
                              const PqAccount& acc) {
    Transaction tx{};
    std::memcpy(tx.sender_nfa, sender.data(), 42);
    std::memcpy(tx.receiver_nfa, receiver.data(), 42);
    tx_set_amount(tx, amount);
    tx_set_fee(tx, fee);
    tx_set_nonce(tx, nonce);
    return pq_sign_b64(tx, acc);
}

std::string transfer_body(const Address& sender, const Address& receiver,
                          uint64_t amount, uint32_t fee, uint32_t nonce,
                          const std::string& witness_b64) {
    return "{\"sender\":\"" + payload_string(sender) + "\","
           "\"receiver\":\"" + payload_string(receiver) + "\","
           "\"amount_vx\":" + std::to_string(static_cast<double>(amount) / 1e8) + ","
           "\"fee_atoms\":" + std::to_string(fee) + ","
           "\"nonce\":" + std::to_string(nonce) + ","
           "\"witness_b64\":\"" + witness_b64 + "\"}";
}

vx::rpc::HttpResponse post(vx::rpc::HttpServer& server, const std::string& path,
                           const std::string& body) {
    vx::rpc::HttpRequest req;
    req.method = "POST";
    req.path = path;
    req.body = body;
    // Every mutator is behind the fail-closed token gate (see the fixture).
    req.headers["authorization"] = std::string("Bearer ") + kTestToken;
    return server.route(req);
}

vx::rpc::HttpResponse get(vx::rpc::HttpServer& server, const std::string& path) {
    vx::rpc::HttpRequest req;
    req.method = "GET";
    req.path = path;
    return server.route(req);
}

// Appends + applies the height-1 protocol mint that funds the demo spender
// (pinned shape, same as the demo chain every node replays).
void fund_demo_spender(vx::storage::BlockStore& store, vx::state::LedgerState& ledger,
                       const Address& demo_spender) {
    BlockBuilder b;
    b.set_height(store.chain_height());
    b.set_timestamp(static_cast<uint64_t>(std::time(nullptr)));
    uint8_t tip[32];
    store.tip_hash(tip);
    b.set_prev_hash(tip);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    Transaction mint{};
    std::memcpy(mint.sender_nfa, "GENESIS_2", 9);
    for (size_t i = 9; i < 42; ++i) mint.sender_nfa[i] = '0';
    std::memcpy(mint.receiver_nfa, demo_spender.data(), 42);
    tx_set_amount(mint, GENESIS_2_MINT_ATOMICS);
    sign_transaction(mint); // system sender: structural digest only
    ASSERT_TRUE(b.add_transaction(mint));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
    ASSERT_TRUE(store.append_block(f));
    ASSERT_TRUE(ledger.apply_block(BlockView(f)).ok);
}

struct AdmissionChain {
    std::string dir;
    std::unique_ptr<vx::storage::BlockStore> store;
    std::unique_ptr<vx::state::LedgerState> ledger;
    std::unique_ptr<vx::rpc::HttpServer> server;
    PqAccount demo{};       // the demo spender key (public protocol constant)
    Address spender{};      // genesis2 mint receiver == demo.addr
    Address recv{};

    explicit AdmissionChain(const char* tag)
        : dir(temp_dir(tag)) {
        // The stage_D seam endpoints (/api/mempool/submit, /api/mempool/seal)
        // sit behind the fail-closed RPC auth gate like every other mutator;
        // the fixture configures a token and the post() helper presents it
        // (server reads the token ONCE at construction).
        ::setenv("VX_RPC_TOKEN", kTestToken, 1);
        store = std::make_unique<vx::storage::BlockStore>(dir + "/ledger.vxb",
                                                          "genesis.bin", 8);
        ledger = std::make_unique<vx::state::LedgerState>();
        // Replay genesis (block 0) into state, as every node start does.
        const auto* g = store->get_block(0);
        EXPECT_NE(g, nullptr);
        if (!g) return;
        BlockFrame gf;
        std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
        EXPECT_TRUE(ledger->apply_block(BlockView(gf)).ok);

        demo = make_pq_account("VX_DEMO_SPENDER_SK_V1");
        spender = genesis2_mint_receiver_payload();
        fund_demo_spender(*store, *ledger, spender);
        recv = addr_of("NFA_ADMIT_SINK_0000000000000000000000000000");

        server = std::make_unique<vx::rpc::HttpServer>(*store, *ledger, 0, dir);
    }

    ~AdmissionChain() { std::filesystem::remove_all(dir); }
};

} // namespace

// -- 1. Admission is observable: a submitted tx sits in the mempool until a
// seal runs, and a submit alone produces no block.
TEST(VortexMempoolAdmissionTest, MempoolSubmitVisibleInStats) {
    AdmissionChain c("vx_admit_stats");
    const std::string wit = sign_transfer_b64(c.spender, c.recv, 700000000u, 100, 0, c.demo);
    ASSERT_FALSE(wit.empty());

    const uint64_t height_before = c.store->chain_height();
    const auto res = post(*c.server, "/api/mempool/submit",
                          transfer_body(c.spender, c.recv, 700000000u, 100, 0, wit));
    ASSERT_EQ(res.status_code, 200) << res.body;
    EXPECT_NE(res.body.find("\"status\":\"accepted\""), std::string::npos) << res.body;
    EXPECT_NE(res.body.find("\"mempool_count\":1"), std::string::npos) << res.body;

    // Observable in the stats endpoint too.
    const auto stats = get(*c.server, "/api/mempool/zk_stats");
    ASSERT_EQ(stats.status_code, 200);
    EXPECT_NE(stats.body.find("\"count\":1"), std::string::npos) << stats.body;

    // Admission only: no block was produced, nothing applied yet.
    EXPECT_EQ(c.store->chain_height(), height_before);
    EXPECT_TRUE(c.ledger->balance_of(c.recv) == U128{});
    // The pending tx reserved the sender's cost against the ledger balance.
    EXPECT_EQ(c.ledger->balance_of(c.spender), U128(GENESIS_2_MINT_ATOMICS));
}

// -- 2. The mempool admission gate refuses a second pending spend of the
// same sender/nonce while the first is unsealed.
TEST(VortexMempoolAdmissionTest, AdmissionRejectsSecondSameNonce) {
    AdmissionChain c("vx_admit_dup");
    const std::string wit = sign_transfer_b64(c.spender, c.recv, 700000000u, 100, 0, c.demo);
    ASSERT_FALSE(wit.empty());
    const std::string body = transfer_body(c.spender, c.recv, 700000000u, 100, 0, wit);

    ASSERT_EQ(post(*c.server, "/api/mempool/submit", body).status_code, 200);
    const auto second = post(*c.server, "/api/mempool/submit", body);
    EXPECT_EQ(second.status_code, 403) << second.body;
    EXPECT_NE(second.body.find("mempool admission refused"), std::string::npos)
        << second.body;
    // Exactly one pending tx.
    const auto stats = get(*c.server, "/api/mempool/zk_stats");
    EXPECT_NE(stats.body.find("\"count\":1"), std::string::npos) << stats.body;
}

// -- 3. Sealing drains the pool through the miner's flow and applies the
// block: receiver credited, sender debited amount + fee, mempool empty.
TEST(VortexMempoolAdmissionTest, SealAppliesToLedger) {
    AdmissionChain c("vx_admit_seal");
    const uint64_t amount = 700000000u;
    const uint32_t fee = 100;
    const std::string wit = sign_transfer_b64(c.spender, c.recv, amount, fee, 0, c.demo);
    ASSERT_EQ(post(*c.server, "/api/mempool/submit",
                   transfer_body(c.spender, c.recv, amount, fee, 0, wit)).status_code, 200);

    const auto seal = post(*c.server, "/api/mempool/seal", "{}");
    ASSERT_EQ(seal.status_code, 200) << seal.body;
    EXPECT_NE(seal.body.find("\"status\":\"ok\""), std::string::npos) << seal.body;

    // Ledger applied the sealed block.
    EXPECT_EQ(c.ledger->balance_of(c.recv), U128(amount));
    EXPECT_EQ(c.ledger->balance_of(c.spender),
              U128(GENESIS_2_MINT_ATOMICS) - U128(amount) - U128(fee));
    EXPECT_EQ(c.ledger->get_next_nonce(c.spender), 1u);
    // Mempool drained by remove_sealed.
    const auto stats = get(*c.server, "/api/mempool/zk_stats");
    EXPECT_NE(stats.body.find("\"count\":0"), std::string::npos) << stats.body;
}

// -- 4. /api/transfer keeps its response contract and now admits through
// the mempool + miner sealing path.
TEST(VortexMempoolAdmissionTest, TransferEndpointSealsThroughMempool) {
    AdmissionChain c("vx_admit_transfer");
    const uint64_t amount = 300000000u;
    const uint32_t fee = 100;
    const std::string wit = sign_transfer_b64(c.spender, c.recv, amount, fee, 0, c.demo);
    ASSERT_FALSE(wit.empty());

    const auto res = post(*c.server, "/api/transfer",
                          transfer_body(c.spender, c.recv, amount, fee, 0, wit));
    ASSERT_EQ(res.status_code, 200) << res.body;
    EXPECT_NE(res.body.find("\"status\":\"ok\""), std::string::npos) << res.body;
    EXPECT_NE(res.body.find("\"block_hash_hex\""), std::string::npos) << res.body;
    EXPECT_NE(res.body.find("\"sealed\":true"), std::string::npos) << res.body;

    EXPECT_EQ(c.ledger->balance_of(c.recv), U128(amount));
    EXPECT_EQ(c.ledger->get_next_nonce(c.spender), 1u);
    // The sealed tx left the mempool (remove_sealed after apply).
    const auto stats = get(*c.server, "/api/mempool/zk_stats");
    EXPECT_NE(stats.body.find("\"count\":0"), std::string::npos) << stats.body;
}

// -- 5. The witness gate precedes admission: a keyless transfer request is
// refused and nothing enters the mempool.
TEST(VortexMempoolAdmissionTest, UnwitnessedTransferRefused) {
    AdmissionChain c("vx_admit_unwit");
    const std::string body = transfer_body(c.spender, c.recv, 700000000u, 100, 0, "");
    const auto res = post(*c.server, "/api/mempool/submit", body);
    EXPECT_EQ(res.status_code, 403);
    EXPECT_NE(res.body.find("PQ witness required"), std::string::npos) << res.body;
    const auto stats = get(*c.server, "/api/mempool/zk_stats");
    EXPECT_NE(stats.body.find("\"count\":0"), std::string::npos) << stats.body;
}

// -- 6. Audit F13: the ledger classifies coinbase mints by SENDER prefix
// (GENESIS*/MINER_*), so a user-signed tx carrying a system prefix is
// mint-shaped consensus material. Admission rejects the shape outright -
// before any cryptographic work - and a zero-amount transfer (no value
// flow, nonce-slot burn) is refused on the same principle.
TEST(VortexMempoolAdmissionTest, SystemPrefixSenderAndZeroAmountRefused) {
    AdmissionChain c("vx_admit_f13");

    const std::string miner_body =
        "{\"sender\":\"MINER_000000000000000000000000000000000000000000\","
        "\"receiver\":\"" + payload_string(c.recv) + "\","
        "\"amount_vx\":1.0,\"fee_atoms\":100,\"nonce\":0,"
        "\"witness_b64\":\"AAAA\"}";
    const auto res1 = post(*c.server, "/api/mempool/submit", miner_body);
    EXPECT_EQ(res1.status_code, 403) << res1.body;
    EXPECT_NE(res1.body.find("system sender prefixes"), std::string::npos) << res1.body;

    const std::string genesis_body =
        "{\"sender\":\"GENESIS_20000000000000000000000000000000000000000\","
        "\"receiver\":\"" + payload_string(c.recv) + "\","
        "\"amount_vx\":1.0,\"fee_atoms\":100,\"nonce\":0,"
        "\"witness_b64\":\"AAAA\"}";
    const auto res2 = post(*c.server, "/api/mempool/submit", genesis_body);
    EXPECT_EQ(res2.status_code, 403) << res2.body;
    EXPECT_NE(res2.body.find("system sender prefixes"), std::string::npos) << res2.body;

    const std::string zero_body =
        "{\"sender\":\"" + payload_string(c.spender) + "\","
        "\"receiver\":\"" + payload_string(c.recv) + "\","
        "\"amount_vx\":0.0,\"fee_atoms\":100,\"nonce\":0,"
        "\"witness_b64\":\"AAAA\"}";
    const auto res3 = post(*c.server, "/api/mempool/submit", zero_body);
    // The TDI screen refuses non-positive amounts before the explicit
    // zero-amount gate is reached; both layers answer 403 and nothing
    // enters the pool.
    EXPECT_EQ(res3.status_code, 403) << res3.body;
    EXPECT_NE(res3.body.find("\"tdi\":0"), std::string::npos) << res3.body;

    // Nothing reached the pool through any of the three refusals.
    const auto stats = get(*c.server, "/api/mempool/zk_stats");
    EXPECT_NE(stats.body.find("\"count\":0"), std::string::npos) << stats.body;
}
