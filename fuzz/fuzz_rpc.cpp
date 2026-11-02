// libFuzzer target: the JSON RPC surface.
//
// Byte 0 selects the HTTP method (real or garbage), byte 1 selects a path
// from the live route table so inputs reach handler depth instead of
// wandering into 404s, and the rest is the request body (4 KiB cap).
//
// Invariants exercised per input:
//  - no crash, no hang, no exception escaping HttpServer::route();
//  - a GET never mutates the chain tip;
//  - every response is produced (route catches handler exceptions and
//    answers 500 instead of unwinding).
//
// The server is constructed once per process against a private temp
// data dir replayed from genesis — no socket is ever bound (port 0,
// start() is never called).
#include "vx/rpc/http_server.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>

namespace {

struct RouteSpec {
    const char* method;
    const char* path;
};

// Mirrors HttpServer::dispatch. Keep in sync with the route table there.
const RouteSpec kRoutes[] = {
    {"GET", "/api/status"},                       {"GET", "/api/blocks"},
    {"GET", "/api/accounts"},                     {"POST", "/api/transfer"},
    {"POST", "/api/security/audit"},              {"POST", "/api/crypto/lab"},
    {"GET", "/api/vault/memory"},                 {"POST", "/api/vault/action"},
    {"POST", "/api/zk/derive_matrix"},            {"POST", "/api/zk/recover_shamir"},
    {"POST", "/api/zk/proof_of_life"},            {"POST", "/api/zk/audit_view"},
    {"POST", "/api/neural/simulate"},             {"GET", "/api/crypto/canonical"},
    {"GET", "/api/mempool/zk_stats"},             {"GET", "/api/swarm/peers"},
    {"POST", "/api/swarm/simulate_split_reorg"},  {"GET", "/api/swarm/dandelion_stats"},
    {"POST", "/api/swarm/relay_cocoon"},          {"POST", "/api/vm/execute_trace"},
    {"GET", "/api/state/trie_root"},              {"POST", "/api/state/prove"},
    {"POST", "/api/mempool/mev_audit"},           {"GET", "/api/consensus/finality_status"},
    {"POST", "/api/consensus/finalize_gqc"},      {"GET", "/api/mempool/pipeline_benchmark"},
    {"POST", "/api/zk/stealth_envelope"},         {"POST", "/api/zk/ivk_scan"},
    {"POST", "/api/vault/ephemeral_sign"},        {"POST", "/api/vm/htlc_swap"},
    {"GET", "/api/telemetry/rdtsc"},              {"POST", "/api/security/chaos_fuzz"},
    {"POST", "/api/crypto/pq_sign"},              {"POST", "/api/crypto/pq_verify"},
};
constexpr size_t kRouteCount = sizeof(kRoutes) / sizeof(kRoutes[0]);

// One accepted transfer appends a 64 KiB frame to the temp ledger; bound
// the growth so long runs cannot balloon disk usage.
constexpr uint64_t kMaxChainHeight = 4096;

std::string make_temp_dir() {
    char tmpl[] = "/tmp/vx_fuzz_rpc_XXXXXX";
    if (char* d = ::mkdtemp(tmpl)) return std::string(d);
    return "/tmp/vx_fuzz_rpc_fallback";
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using vx::rpc::HttpRequest;

    static std::unique_ptr<vx::storage::BlockStore> store;
    static std::unique_ptr<vx::state::LedgerState> ledger;
    static std::unique_ptr<vx::rpc::HttpServer> server;
    static std::string env_dir;
    if (!server) {
        env_dir = make_temp_dir();
        store = std::make_unique<vx::storage::BlockStore>(
            env_dir + "/ledger.vxb", env_dir + "/genesis.bin");
        ledger = std::make_unique<vx::state::LedgerState>();
        // Replay the genesis chain so balances and height are live, exactly
        // as a serving node does on startup.
        for (uint64_t h = 0; h < store->chain_height(); ++h) {
            auto* raw = store->get_block(h);
            if (!raw) break;
            vx::blockchain::BlockView v{std::span<const uint8_t, 65536>(
                reinterpret_cast<const uint8_t*>(raw), 65536)};
            (void)ledger->apply_block(v);
        }
        // Port 0 + no start(): the RPC is exercised purely as a callable
        // unit, no listener, no worker threads.
        server = std::make_unique<vx::rpc::HttpServer>(*store, *ledger, 0, env_dir);
    }

    if (size < 2) return 0;

    const uint8_t method_byte = data[0];
    std::string method;
    if (method_byte == 0) {
        method = "GET";
    } else if (method_byte == 1) {
        method = "POST";
    } else if (method_byte == 2) {
        method = "OPTIONS";
    } else {
        // Deliberately hostile method strings: unterminated, binary, empty.
        method.assign(reinterpret_cast<const char*>(data + 2),
                      std::min<size_t>(3, size - 2));
    }

    const RouteSpec& spec = kRoutes[data[1] % kRouteCount];

    HttpRequest req;
    req.method = std::move(method);
    req.path = spec.path;
    req.body.assign(reinterpret_cast<const char*>(data + 2),
                    std::min<size_t>(size - 2, 4096));

    // GET invariance: reading must never move the tip.
    uint8_t tip_before[32] = {};
    uint8_t tip_after[32] = {};
    const bool check_get = (req.method == "GET");
    if (check_get) store->tip_hash(tip_before);

    const bool post_transfer_skipped =
        (req.method == "POST" && req.path == "/api/transfer" &&
         store->chain_height() >= kMaxChainHeight);
    if (!post_transfer_skipped) {
        const auto res = server->route(req);
        (void)res;
    }

    if (check_get) {
        store->tip_hash(tip_after);
        if (std::memcmp(tip_before, tip_after, 32) != 0) {
            // Report as a crash so libFuzzer surfaces the input.
            __builtin_trap();
        }
    }
    return 0;
}
