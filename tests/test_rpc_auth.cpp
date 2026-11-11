// RPC auth token suite (BACKLOG 0.10, C2).
//
// The mutating /api/* endpoints require the auth token (VX_RPC_TOKEN or
// VX_RPC_TOKEN_FILE, read once at server construction); with no token
// configured they fail closed with 401; read-only endpoints stay open.
// The server is exercised purely as a callable unit (route(), no socket),
// exactly like fuzz_rpc does.
#include <gtest/gtest.h>

#include "vx/rpc/http_server.hpp"
#include "vx/blockchain/block.hpp"

#include <unistd.h>

#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

namespace {

// Unique per test invocation, created EXCLUSIVELY (zero-trust review P2-5:
// a fixed name + remove_all could delete a planted path or share a planted
// directory; a unique name that must not already exist cannot be hijacked).
std::string make_temp_dir(const char* tag) {
    static std::atomic<unsigned> seq{0};
    const std::string dir = std::string("/tmp/vx_rpc_auth_") + tag + "_" +
                            std::to_string(::getpid()) + "_" +
                            std::to_string(seq.fetch_add(1));
    if (!std::filesystem::create_directory(dir)) {
        std::fprintf(stderr, "make_temp_dir: path already exists: %s\n", dir.c_str());
        std::abort();
    }
    return dir;
}

struct ServerEnv {
    std::unique_ptr<vx::storage::BlockStore> store;
    std::unique_ptr<vx::state::LedgerState> ledger;
    std::unique_ptr<vx::rpc::HttpServer> server;
    std::string dir;
};

// Build a serving-node-like stack in a temp dir (genesis auto-seeded),
// with the auth environment the caller requests.
ServerEnv make_server(const char* tag, const char* token, const char* token_file_value,
                      const char* token_file_path) {
    if (token != nullptr) {
        ::setenv("VX_RPC_TOKEN", token, 1);
    } else {
        ::unsetenv("VX_RPC_TOKEN");
    }
    if (token_file_path != nullptr) {
        ::setenv("VX_RPC_TOKEN_FILE", token_file_path, 1);
    } else {
        ::unsetenv("VX_RPC_TOKEN_FILE");
    }

    ServerEnv env;
    env.dir = make_temp_dir(tag);
    env.store = std::make_unique<vx::storage::BlockStore>(env.dir + "/ledger.vxb",
                                                          env.dir + "/genesis.bin", 8);
    env.ledger = std::make_unique<vx::state::LedgerState>();
    for (uint64_t h = 0; h < env.store->chain_height(); ++h) {
        auto* raw = env.store->get_block(h);
        if (!raw) break;
        vx::blockchain::BlockView v{std::span<const uint8_t, 65536>(
            reinterpret_cast<const uint8_t*>(raw), 65536)};
        (void)env.ledger->apply_block(v);
    }
    env.server = std::make_unique<vx::rpc::HttpServer>(*env.store, *env.ledger, 0, env.dir);
    (void)token_file_value;
    return env;
}

vx::rpc::HttpRequest request(std::string method, std::string path, std::string body,
                             const char* authorization = nullptr) {
    vx::rpc::HttpRequest req;
    req.method = std::move(method);
    req.path = std::move(path);
    req.body = std::move(body);
    if (authorization != nullptr) req.headers["authorization"] = authorization;
    return req;
}

constexpr const char* kToken = "s3cr3t-t0k3n";

} // namespace

// No token configured anywhere: every mutating endpoint fails closed with
// 401, and the read-only surface stays open.
TEST(VortexRpcAuthTest, NoTokenFailsClosed) {
    const auto env = make_server("notoken", nullptr, nullptr, nullptr);

    EXPECT_EQ(env.server->route(request("POST", "/api/transfer", "{}")).status_code, 401);
    EXPECT_EQ(env.server->route(request("POST", "/api/vault/action",
                                        R"({"action":"commit","payload":"00"})"))
                  .status_code,
              401);
    EXPECT_EQ(env.server->route(request("POST", "/api/consensus/finalize_gqc", "")).status_code,
              401);
    EXPECT_EQ(env.server->route(request("POST", "/api/crypto/pq_sign", "")).status_code, 401);

    // Read-only endpoints stay open.
    EXPECT_EQ(env.server->route(request("GET", "/api/status", "")).status_code, 200);
    EXPECT_EQ(env.server->route(request("GET", "/api/accounts", "")).status_code, 200);
    // Public binary surface pass: /api/blocks is now resource-heavy (O(chain)
    // walk under state_mutex_) — it must gate like the other heavy classes.
    EXPECT_EQ(env.server->route(request("GET", "/api/blocks", "")).status_code, 401);
    // Resource-heavy endpoints share the same fail-closed gate (P1-2): both
    // a state_mutex_-holding POST and CPU-bound GETs must 401 without a
    // token, unlike plain read-only GETs above.
    EXPECT_EQ(env.server->route(
                  request("POST", "/api/security/audit", R"({"attack_type":"dust_spam_tdi}")"))
                  .status_code,
              401);
    EXPECT_EQ(env.server->route(request("GET", "/api/mempool/pipeline_benchmark", "")).status_code,
              401);
    EXPECT_EQ(env.server->route(request("GET", "/api/vm/execute_trace", "")).status_code, 401);
    EXPECT_EQ(env.server->route(request("POST", "/api/neural/simulate", "{}")).status_code, 401);
    EXPECT_EQ(env.server->route(request("GET", "/api/mempool/mev_audit", "")).status_code, 401);
    EXPECT_EQ(env.server->route(request("POST", "/api/zk/ivk_scan", "{}")).status_code, 401);
    EXPECT_EQ(env.server->route(request("POST", "/api/swarm/relay_cocoon", "{}")).status_code, 401);
    // Round-2 review P2: the remaining full-run state_mutex_ holders.
    EXPECT_EQ(env.server->route(request("POST", "/api/zk/stealth_envelope", "{}")).status_code,
              401);
    EXPECT_EQ(env.server->route(request("POST", "/api/state/prove", "{}")).status_code, 401);
    // Security review P3 (2026-11-12): a full 7-tier key derivation plus
    // proof generation/verification per POST — same burn class as
    // derive_matrix, gated the same way.
    EXPECT_EQ(env.server->route(request("POST", "/api/zk/proof_of_life", "{}")).status_code, 401);
    EXPECT_EQ(env.server->route(request("GET", "/api/mempool/zk_stats", "")).status_code, 200);
}

// Public binary surface pass (2026-11-12): sensitive endpoints — key-material
// oracles, hardware-fingerprint disclosures and CPU/recon burns — share the
// fail-closed token gate. Unauthenticated: 401. With the token: the handler
// runs (200).
TEST(VortexRpcAuthTest, SensitiveEndpointsFailClosed) {
    const auto env = make_server("sensitive", kToken, nullptr, nullptr);

    // Without token: every sensitive class endpoint answers 401.
    EXPECT_EQ(env.server->route(request("POST", "/api/crypto/lab", "{}")).status_code, 401);
    EXPECT_EQ(env.server->route(request("GET", "/api/crypto/canonical", "")).status_code, 401);
    EXPECT_EQ(env.server->route(request("POST", "/api/zk/derive_matrix", "{}")).status_code, 401);
    EXPECT_EQ(env.server->route(request("POST", "/api/zk/recover_shamir", "{}")).status_code, 401);
    EXPECT_EQ(env.server->route(request("GET", "/api/telemetry/rdtsc", "")).status_code, 401);
    EXPECT_EQ(env.server->route(request("GET", "/api/vault/memory", "")).status_code, 401);

    // With the token the gate passes and the real handler answers.
    EXPECT_EQ(env.server->route(request("GET", "/api/crypto/canonical", "", kToken)).status_code,
              200);
    EXPECT_EQ(env.server->route(request("POST", "/api/zk/derive_matrix", "{}", kToken)).status_code,
              200);
    EXPECT_EQ(env.server->route(request("GET", "/api/vault/memory", "", kToken)).status_code, 200);
}

// Query-string bypass regression (2026-11-12): appending "?x=1" to a gated
// path must never smuggle a request past the gate — the target is split on
// '?' before any path comparison. A read-only endpoint with a query string
// stays open.
TEST(VortexRpcAuthTest, QueryStringCannotBypassGate) {
    const auto env = make_server("qsbypass", kToken, nullptr, nullptr);

    // Gated path + query string: still 401 without the token.
    EXPECT_EQ(env.server->route(request("GET", "/api/blocks?last=10", "")).status_code, 401);
    EXPECT_EQ(env.server->route(request("POST", "/api/transfer?x=1", "{}")).status_code, 401);
    EXPECT_EQ(env.server->route(request("GET", "/api/crypto/canonical?v=2", "")).status_code, 401);

    // Read-only path + query string: stays open.
    EXPECT_EQ(env.server->route(request("GET", "/api/status?v=2", "")).status_code, 200);
    EXPECT_EQ(env.server->route(request("GET", "/api/accounts?full=1", "")).status_code, 200);

    // Empty and bare queries never flip a gated path open either.
    EXPECT_EQ(env.server->route(request("GET", "/api/blocks?", "")).status_code, 401);
}

// Positive-path coverage of the bounded /api/blocks window (security
// review P3-5, 2026-11-12) plus the single-block trailing-comma regression
// (review P2-1): on a 2-block chain, ?height=0 once emitted "...},]"
// (malformed JSON) because the comma condition compared against the chain
// height instead of the window end.
TEST(VortexRpcAuthTest, BlocksWindowSemantics) {
    const auto env = make_server("blockswin", kToken, nullptr, nullptr);

    // Grow the chain to 2 blocks: an empty frame (no transactions — no
    // witness bindings needed) sealed straight into the store.
    {
        vx::blockchain::BlockBuilder b;
        b.set_height(env.store->chain_height());
        b.set_timestamp(static_cast<uint64_t>(std::time(nullptr)));
        uint8_t tip[32];
        env.store->tip_hash(tip);
        b.set_prev_hash(tip);
        const std::array<uint8_t, 384> coords{};
        b.set_attractor_coords(coords.data());
        b.finalize();
        vx::blockchain::BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), vx::blockchain::BLOCK_SIZE_BYTES);
        ASSERT_TRUE(vx::blockchain::seal_pogw_nonce(f, env.store->required_pogw_bits()));
        ASSERT_TRUE(env.store->append_block(f)) << env.store->last_error();
    }
    ASSERT_EQ(env.store->chain_height(), 2u);

    const auto body_of = [&](const std::string &target) {
        return env.server->route(request("GET", target, "", kToken)).body;
    };

    // Default window (256 >= chain): both blocks, well-formed separators.
    const std::string full = body_of("/api/blocks");
    EXPECT_NE(full.find("\"height\":0"), std::string::npos);
    EXPECT_NE(full.find("\"height\":1"), std::string::npos);
    EXPECT_EQ(full.find(",]"), std::string::npos) << full;
    EXPECT_EQ(full.find(",}"), std::string::npos) << full;

    // Single-block mode (the P2-1 regression): point lookups of BOTH
    // heights parse cleanly — no trailing comma, only the asked block.
    const std::string h0 = body_of("/api/blocks?height=0");
    EXPECT_NE(h0.find("\"height\":0"), std::string::npos);
    EXPECT_EQ(h0.find("\"height\":1"), std::string::npos);
    EXPECT_EQ(h0.find(",]"), std::string::npos) << h0;
    const std::string h1 = body_of("/api/blocks?height=1");
    EXPECT_NE(h1.find("\"height\":1"), std::string::npos);
    EXPECT_EQ(h1.find("\"height\":0"), std::string::npos);
    EXPECT_EQ(h1.find(",]"), std::string::npos) << h1;

    // Out of range: 404, never a fabricated block.
    EXPECT_EQ(env.server->route(request("GET", "/api/blocks?height=2", "", kToken)).status_code,
              404);
    EXPECT_EQ(env.server->route(request("GET", "/api/blocks?height=12345", "", kToken)).status_code,
              404);

    // Tail window: last=1 answers only the tip; last=0 an empty array.
    const std::string tail1 = body_of("/api/blocks?last=1");
    EXPECT_EQ(tail1.find("\"height\":0"), std::string::npos);
    EXPECT_NE(tail1.find("\"height\":1"), std::string::npos);
    const std::string tail0 = body_of("/api/blocks?last=0");
    EXPECT_NE(tail0.find("\"blocks\":[]"), std::string::npos);

    // Parser rules: non-decimal and >19-digit values are ignored, falling
    // back to the default window (both blocks present).
    EXPECT_NE(body_of("/api/blocks?last=abc").find("\"height\":0"), std::string::npos);
    EXPECT_NE(body_of("/api/blocks?last=99999999999999999999").find("\"height\":0"),
              std::string::npos);
}

// Byte-level parser regressions (P2-2) driven through route_raw, which uses
// the same scan_headers as the socket path: look-alike header names and
// duplicate Authorization headers must never authenticate.
TEST(VortexRpcAuthTest, HeaderParsingRegressions) {
    const auto env = make_server("hdrparse", kToken, nullptr, nullptr);

    auto raw_req = [](std::string headers) {
        return "POST /api/transfer HTTP/1.1\r\n" + headers + "\r\n" + "{}";
    };

    // Look-alike names must NOT satisfy the gate (substring-find regression).
    const auto proxy_auth = env.server->route_raw(
        raw_req("Proxy-Authorization: Bearer s3cr3t-t0k3n\r\nContent-Length: 2\r\n\r\n"));
    EXPECT_EQ(proxy_auth.status_code, 401);

    const auto x_auth = env.server->route_raw(
        raw_req("X-Authorization: Bearer s3cr3t-t0k3n\r\nContent-Length: 2\r\n\r\n"));
    EXPECT_EQ(x_auth.status_code, 401);

    // Duplicate Authorization headers fail closed (401), not first-wins.
    const auto dup_auth = env.server->route_raw(raw_req(
        "Authorization: Bearer s3cr3t-t0k3n\r\nAuthorization: Bearer s3cr3t-t0k3n\r\n"
        "Content-Length: 2\r\n\r\n"));
    EXPECT_EQ(dup_auth.status_code, 401);

    // A duplicate Content-Length must not change framing: the first one is
    // kept (smoke through the full raw path).
    const auto dup_cl = env.server->route_raw(
        raw_req("Content-Length: 9999\r\nAuthorization: Bearer s3cr3t-t0k3n\r\n"
                "Content-Length: 2\r\n\r\n"));
    EXPECT_EQ(dup_cl.status_code, 403); // past the gate, refused for keyless body

    // The framing rule itself, asserted directly on the parser (review
    // finding: a route_raw-only check cannot distinguish first-wins from
    // last-wins because no handler sees the raw body).
    {
        const std::string raw =
            "POST /api/transfer HTTP/1.1\r\n"
            "Content-Length: 2\r\n"
            "Authorization: Bearer s3cr3t-t0k3n\r\n"
            "Content-Length: 9999\r\n"
            "\r\n"
            "{}TrailingSmuggledData";
        size_t cl = 0;
        vx::rpc::HttpRequest parsed;
        vx::rpc::HttpServer::scan_headers(raw, raw.find("\r\n\r\n"), cl, parsed);
        EXPECT_EQ(cl, 2u) << "first Content-Length must win (smuggling)";
        EXPECT_EQ(parsed.headers.count("authorization"), 1u);
    }

    // CL framing truncates the body: bytes past the declared length are a
    // pipelined request, never part of this body.
    {
        const std::string raw =
            "POST /api/transfer HTTP/1.1\r\n"
            "Content-Length: 2\r\n\r\n"
            "{}GET /api/status HTTP/1.1\r\n\r\n";
        size_t cl = 0;
        vx::rpc::HttpRequest parsed;
        vx::rpc::HttpServer::scan_headers(raw, raw.find("\r\n\r\n"), cl, parsed);
        EXPECT_EQ(cl, 2u);
    }

    // A single correct header still authenticates through the raw path.
    const auto ok_auth = env.server->route_raw(
        raw_req("Authorization: Bearer s3cr3t-t0k3n\r\nContent-Length: 2\r\n\r\n"));
    EXPECT_EQ(ok_auth.status_code, 403);

    // Garbage bytes produce 400, never a crash or an auth pass.
    EXPECT_EQ(env.server->route_raw("\x01\x02\xffno-crlf-at-all").status_code, 400);
    EXPECT_EQ(env.server->route_raw("").status_code, 400);
}

// A configured token rejects missing and wrong credentials with 401.
TEST(VortexRpcAuthTest, WrongOrMissingTokenRejected) {
    const auto env = make_server("wrongtoken", kToken, nullptr, nullptr);
    const auto req = request("POST", "/api/transfer", "{}");

    // No header at all.
    EXPECT_EQ(env.server->route(req).status_code, 401);
    // Wrong token, bare and Bearer forms.
    EXPECT_EQ(env.server->route(request("POST", "/api/transfer", "{}", "wrong")).status_code, 401);
    EXPECT_EQ(env.server->route(request("POST", "/api/transfer", "{}", "Bearer wrong"))
                  .status_code,
              401);
    // Prefix of the real token (length-difference path of the
    // constant-time compare).
    const std::string token_prefix = std::string(kToken).substr(0, 4);
    EXPECT_EQ(env.server->route(request("POST", "/api/transfer", "{}", token_prefix.c_str()))
                  .status_code,
              401);
    // Wrong token on the other mutating endpoints too.
    EXPECT_EQ(env.server->route(
                  request("POST", "/api/consensus/finalize_gqc", "", "Bearer nope"))
                  .status_code,
              401);
}

// The correct token admits mutating endpoints; responses then come from the
// real handlers (403 for a keyless transfer, 200 for the signer).
TEST(VortexRpcAuthTest, CorrectTokenAccepted) {
    const auto env = make_server("goodtoken", kToken, nullptr, nullptr);

    // The transfer handler runs and refuses the KEYLESS body (403), which
    // proves the request passed the auth gate (401 otherwise).
    const auto transfer = env.server->route(request("POST", "/api/transfer", "{}", kToken));
    EXPECT_EQ(transfer.status_code, 403);

    // Bearer form is accepted too.
    const auto transfer_bearer = env.server->route(
        request("POST", "/api/transfer", "{}", "Bearer s3cr3t-t0k3n"));
    EXPECT_EQ(transfer_bearer.status_code, 403);

    // pq_sign (default caller-seed signer, no demo_key) signs live: 200.
    const auto sign = env.server->route(request("POST", "/api/crypto/pq_sign", "", kToken));
    ASSERT_EQ(sign.status_code, 200);
    EXPECT_NE(sign.body.find("\"ok\":true"), std::string::npos);

    // vault/action commit runs with the token.
    const auto vault = env.server->route(
        request("POST", "/api/vault/action", R"({"action":"commit","payload":"deadbeef"})",
                "Bearer s3cr3t-t0k3n"));
    EXPECT_EQ(vault.status_code, 200);
}

// The token can come from a file (first line, trailing whitespace
// stripped) instead of the environment.
TEST(VortexRpcAuthTest, TokenFromFileAccepted) {
    const std::string tokdir = make_temp_dir("tokfile");
    const std::string tokpath = tokdir + "/rpc.token";
    {
        std::ofstream out(tokpath);
        out << "file-t0k3n-1234\r\n";
    }
    const auto env = make_server("filetoken", nullptr, nullptr, tokpath.c_str());

    EXPECT_EQ(env.server->route(request("POST", "/api/transfer", "{}", "file-t0k3n-1234"))
                  .status_code,
              403); // passed the gate, refused for the keyless body
    EXPECT_EQ(env.server->route(request("POST", "/api/transfer", "{}", "wrong")).status_code, 401);

    std::filesystem::remove_all(tokdir);
}

// An unreadable token file must NOT disable auth: fail closed.
TEST(VortexRpcAuthTest, UnreadableTokenFileFailsClosed) {
    const auto env = make_server("badtokenfile", nullptr, nullptr, "/nonexistent/dir/rpc.token");
    EXPECT_EQ(env.server->route(request("POST", "/api/transfer", "{}", "anything")).status_code,
              401);
}
