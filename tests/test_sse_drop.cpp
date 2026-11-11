// VortexSseDropTest - BACKLOG 2.11 refinement (owner II.2): the SSE drop
// path in HttpServer::broadcast_sse_event.
//
// The Drop Slow Consumer policy removes a client whose push failed
// (EAGAIN/ECONNRESET) and - since the 2026-11-08 refinement - shuts the
// socket down so the client's detached connection thread terminates
// deterministically instead of polling a subscription nothing is pushed
// to (the connection thread owns the fd; broadcast only signals, never
// closes; the security review re-checks membership under sse_mutex_ so a
// recycled fd number is never shut down). This suite is a real-socket
// smoke test of the server's behavior AROUND the drop:
//
//   1. a subscriber that dies with a hard RST (SO_LINGER {1,0}) is
//      reclaimed without wedging, crashing or SIGPIPE - whichever side
//      observes the RST first (the broadcast send or the connection
//      thread's poll loop) handles it;
//   2. the server survives and a NEW subscriber still receives the hello
//      and a LIVE push event - the push path stays healthy across a
//      dropped peer;
//   3. stop() quiesces cleanly afterwards.
//
// HONEST LIMITS (recorded in BACKLOG):
//   - the refinement's own observable - the FIN the dropped client
//     receives - is NOT pinned here. Proving it requires real TCP
//     backpressure (a stopped reader + a filled socket buffer), which on
//     loopback fights send-buffer autotuning and would make the test
//     timing-dependent.
//   - branch reach is a race and the test does not pretend otherwise:
//     after the RST the server-side connection thread usually observes it
//     in poll first and reclaims the fd itself (the correct outcome -
//     broadcast then finds nothing to drop); the drop branch runs only
//     when the broadcast send loses that race. The branch itself is four
//     lines under the mutex; its failure modes (shutdown on -1 / non-
//     socket, SIGPIPE from shutdown - impossible by construction) are
//     excluded by code inspection, and this test pins the invariant that
//     matters operationally: the server and its push path survive peer
//     resets of both kinds.

#include <gtest/gtest.h>
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/rpc/http_server.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace vx::blockchain;

namespace {

std::string temp_dir(const char *tag) {
    auto dir = std::filesystem::temp_directory_path() /
               (std::string(tag) + "_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    return dir.string();
}

uint16_t free_tcp_port() {
    int probe = ::socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_GE(probe, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    EXPECT_EQ(::bind(probe, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)), 0);
    socklen_t alen = sizeof(addr);
    ::getsockname(probe, reinterpret_cast<sockaddr *>(&addr), &alen);
    const uint16_t port = ntohs(addr.sin_port);
    ::close(probe);
    return port;
}

// Connect with retries: start() runs in its own thread, the listener may
// not be accepting yet when the test reaches out.
int connect_port(uint16_t port) {
    for (int i = 0; i < 150; ++i) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(port);
        if (::connect(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0) {
            timeval tv{2, 0}; // every later read is bounded
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            return fd;
        }
        ::close(fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return -1;
}

bool send_all(int fd, const std::string &data) {
    size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (n <= 0)
            return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

// Read whatever is pending (bounded by SO_RCVTIMEO), return false on error
// or on a read that never happened.
bool read_some(int fd, std::string *out) {
    char buf[2048];
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0)
        return false;
    out->append(buf, static_cast<size_t>(n));
    return true;
}

// A coinbase-only frame at the store's tip: the empty witness set
// auto-commits the empty constant, so the intake gate matches and the
// APPLIED path fires the SSE broadcast.
BlockFrame coinbase_frame(vx::storage::BlockStore &store) {
    BlockBuilder b;
    b.set_height(store.chain_height());
    b.set_timestamp(store.get_block(store.chain_height() - 1)->header.timestamp + 1);
    uint8_t tip[32];
    store.tip_hash(tip);
    b.set_prev_hash(tip);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    EXPECT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
    return f;
}

} // namespace

TEST(VortexSseDropTest, DroppedClientBranchKeepsPushAlive) {
    const std::string dir = temp_dir("vx_sse_drop");
    auto store = std::make_unique<vx::storage::BlockStore>(dir + "/ledger.vxb", "genesis.bin", 8);
    auto ledger = std::make_unique<vx::state::LedgerState>();
    const auto *g = store->get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger->apply_block(BlockView(gf)).ok);

    const uint16_t port = free_tcp_port();
    auto server = std::make_unique<vx::rpc::HttpServer>(*store, *ledger, port, dir);
    std::thread accept_thread([&server] { server->start(); });

    // 1. Client A subscribes, reads the conforming head, then dies with a
    //    hard RST. The next broadcast send must fail - never wedge, never
    //    SIGPIPE - and run the dropped branch (shutdown + erase).
    int a = connect_port(port);
    ASSERT_GE(a, 0) << "RPC listener never accepted";
    ASSERT_TRUE(send_all(a, "GET /api/events HTTP/1.1\r\nHost: t\r\n\r\n"));
    std::string head;
    bool got_head = false;
    for (int i = 0; i < 20 && !got_head; ++i) {
        if (!read_some(a, &head))
            break;
        got_head = head.find("200 OK") != std::string::npos &&
                   head.find("text/event-stream") != std::string::npos;
    }
    ASSERT_TRUE(got_head) << "SSE response head missing: " << head;
    // drain the hello event so the RST carries unread data (guaranteed RST)
    (void)read_some(a, &head);
    linger lg{};
    lg.l_onoff = 1;
    lg.l_linger = 0;
    ASSERT_EQ(::setsockopt(a, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)), 0);
    ::close(a);
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // RST lands

    BlockFrame f1 = coinbase_frame(*store);
    EXPECT_TRUE(server->apply_remote_frame(f1.data()))
        << "coinbase-only frame refused - the drop branch was never reached";

    // 2. The server survived the branch. A fresh subscriber gets the head,
    //    the hello, and a LIVE push event on the next apply.
    int b = connect_port(port);
    ASSERT_GE(b, 0);
    ASSERT_TRUE(send_all(b, "GET /api/events HTTP/1.1\r\nHost: t\r\n\r\n"));
    std::string stream;
    bool got_hello = false;
    for (int i = 0; i < 20 && !got_hello; ++i) {
        if (!read_some(b, &stream))
            break;
        got_hello = stream.find("connected") != std::string::npos;
    }
    ASSERT_TRUE(got_hello) << "new subscriber never received the hello: " << stream;

    BlockFrame f2 = coinbase_frame(*store);
    EXPECT_TRUE(server->apply_remote_frame(f2.data()));
    std::string pushed;
    bool got_event = false;
    for (int i = 0; i < 20 && !got_event; ++i) {
        if (!read_some(b, &pushed))
            break;
        got_event = pushed.find("block_sealed") != std::string::npos;
    }
    EXPECT_TRUE(got_event) << "the live push path died with the dropped branch: " << pushed;

    // 3. Polite teardown: B leaves first (its detached thread observes the
    //    EOF), then stop() quiesces and the accept loop joins. The settle
    //    after stop() keeps the detached SSE threads from touching members
    //    that die with the server at scope exit (review P3).
    ::close(b);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    server->stop();
    accept_thread.join();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}
