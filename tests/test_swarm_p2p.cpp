// VortexSwarmP2PTest — unit tests (test #10)
//
// Verifies:
//   1. WireHeader is strictly 24 bytes.
//   2. A single flipped bit in the payload is rejected via SSE4.2 CRC32C.
//   3. A real 65536-byte block round-trips between two TCP sockets over VX60.
//   4. Full split-brain reorg: Node A (2 blocks) vs Node B (4 blocks) ->
//      both converge at height 4 with identical tip hashes.

#include <gtest/gtest.h>
#include "vx/net/swarm_node.hpp"
#include "vx/crypto/simd_accel.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

namespace {

// VX60 helpers mirroring the wire helpers under test.
using vx::net::WireHeader;
using vx::net::WireMsgType;
using vx::net::VX60_MAGIC;
using namespace vx::crypto::pq;

// ── BACKLOG 1.5 P0 GATE test helpers ────────────────────────────────────────

// Ephemeral loopback port probe: bind port 0, read, close.
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

// Connect a raw client socket to a loopback listener port with a receive
// deadline, so a missing response can never hang the suite.
int connect_client(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_GE(fd, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    EXPECT_EQ(::connect(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)), 0);
    timeval tv{};
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    EXPECT_EQ(::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)), 0);
    return fd;
}

// Blocking read of one full VX60 packet (header + payload). Returns false on
// EOF/timeout/short read.
bool read_packet(int fd, WireHeader &hdr, std::vector<uint8_t> &payload) {
    size_t off = 0;
    auto *hb = reinterpret_cast<uint8_t *>(&hdr);
    while (off < sizeof(hdr)) {
        const ssize_t n = ::recv(fd, hb + off, sizeof(hdr) - off, 0);
        if (n <= 0)
            return false;
        off += static_cast<size_t>(n);
    }
    payload.assign(hdr.payload_len, 0);
    off = 0;
    while (off < payload.size()) {
        const ssize_t n = ::recv(fd, payload.data() + off, payload.size() - off, 0);
        if (n <= 0)
            return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

// Send one VX60 packet with a correct CRC (header + payload).
bool send_packet(int fd, WireMsgType type, const std::vector<uint8_t> &payload) {
    WireHeader h =
        vx::net::SwarmNode::make_header(type, static_cast<uint32_t>(payload.size()), 0xCAFEF00D);
    h.crc32c = vx::net::compute_wire_crc32c(payload.data(), payload.size());
    if (::send(fd, &h, sizeof(h), 0) != static_cast<ssize_t>(sizeof(h)))
        return false;
    size_t off = 0;
    while (off < payload.size()) {
        const ssize_t n = ::send(fd, payload.data() + off, payload.size() - off, 0);
        if (n <= 0)
            return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

// Deterministic test key material + a valid one-window rollover certificate
// (same construction the wiring test uses).
std::array<uint8_t, 32> test_bytes(const char *tag, uint64_t counter) {
    std::vector<uint8_t> bytes;
    bytes.reserve(std::strlen(tag) + 8);
    bytes.insert(bytes.end(), tag, tag + std::strlen(tag));
    for (int i = 0; i < 8; ++i)
        bytes.push_back(static_cast<uint8_t>(counter >> (i * 8)));
    std::array<uint8_t, 32> out{};
    vx::blockchain::VortexSponge256::compute(bytes.data(), bytes.size(), out.data());
    return out;
}

vx::crypto::pq::PqRolloverCert make_valid_cert(const char *tag) {
    const auto master = test_bytes(tag, 1);
    const auto pub_seed = pub_seed_from_sk(master);
    vx::crypto::pq::PqRolloverCert cert;
    const auto d = test_bytes(tag, 2);
    std::memcpy(cert.sender.data(), "PQA", 3);
    std::memcpy(cert.sender.data() + 3, d.data(), 32);
    for (size_t i = 35; i < cert.sender.size(); ++i)
        cert.sender[i] = static_cast<uint8_t>('A' + (i % 26));
    cert.from_window = 0;
    cert.to_window = 1;
    cert.old_root = xmss_root_tree(master, pub_seed, 0);
    cert.new_root = xmss_root_tree(master, pub_seed, 1);
    cert.witness = pq_sign_rollover(master, 0, 1, nullptr);
    return cert;
}

// Exchange one packet over a socketpair with one payload bit flipped.
bool send_flipped_packet(int fd, const std::vector<uint8_t>& payload) {
    WireHeader h = vx::net::SwarmNode::make_header(WireMsgType::RAW_BLOCK_64K,
                                                   static_cast<uint32_t>(payload.size()), 42);
    h.crc32c = vx::net::compute_wire_crc32c(payload.data(), payload.size());
    // Corrupt: flip one bit in the payload
    std::vector<uint8_t> corrupted = payload;
    corrupted[1234] ^= 0x01;
    ssize_t n = ::send(fd, &h, sizeof(h), 0);
    if (n != sizeof(h)) return false;
    size_t off = 0;
    while (off < corrupted.size()) {
        n = ::send(fd, corrupted.data() + off, corrupted.size() - off, 0);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

} // namespace

// ── 1. WireHeader invariant ─────────────────────────────────────────────────

TEST(VortexSwarmP2PTest, WireHeaderIsExactly24Bytes) {
    static_assert(sizeof(WireHeader) == 24, "wire invariant");
    EXPECT_EQ(sizeof(WireHeader), 24u);

    WireHeader h = vx::net::SwarmNode::make_header(WireMsgType::HANDSHAKE, 48, 0xAABBCCDD);
    EXPECT_EQ(h.magic, VX60_MAGIC);
    EXPECT_EQ(h.magic, 0x56583630u);
    EXPECT_EQ(h.msg_type, static_cast<uint8_t>(WireMsgType::HANDSHAKE));
    EXPECT_EQ(h.reserved, 0);
    EXPECT_EQ(h.payload_len, 48u);
    EXPECT_EQ(h.peer_nonce, 0xAABBCCDDULL);
    EXPECT_TRUE(vx::net::wire_header_plausible(h));

    // Bad magic / oversized payload rejected by the plausibility gate
    h.magic = 0xDEADBEEF;
    EXPECT_FALSE(vx::net::wire_header_plausible(h));
    h.magic = VX60_MAGIC;
    h.payload_len = 65537;
    EXPECT_FALSE(vx::net::wire_header_plausible(h));
}

// ── 2. CRC32C corruption detection ──────────────────────────────────────────

TEST(VortexSwarmP2PTest, CorruptedPacketDroppedByCrc32c) {
    // Hardware CRC32C self-check against the scalar reference
    std::vector<uint8_t> data(4096);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i * 31 + 7);
    const uint32_t crc1 = vx::crypto::crc32c_hw(data.data(), data.size());
    const uint32_t crc2 = vx::crypto::crc32c_scalar(data.data(), data.size());
    EXPECT_EQ(crc1, crc2);

    // A single flipped bit must change the CRC
    data[1234] ^= 0x01;
    const uint32_t crc_flipped = vx::crypto::crc32c_hw(data.data(), data.size());
    EXPECT_NE(crc1, crc_flipped);
}

TEST(VortexSwarmP2PTest, RecvPacketRejectsSingleBitFlip) {
    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    std::vector<uint8_t> payload(8192, 0xAB);
    vx::net::SwarmNode node;

    // Sender writes a packet whose payload has 1 bit flipped after CRC compute.
    std::thread sender([&]() { ASSERT_TRUE(send_flipped_packet(fds[0], payload)); });

    WireHeader hdr{};
    std::vector<uint8_t> got;
    // Note: SwarmNode::recv_packet is a member; exercise it directly.
    const bool ok = node.recv_packet(fds[1], hdr, got);
    EXPECT_FALSE(ok); // corrupted -> dropped
    EXPECT_EQ(node.corrupted_packets_dropped(), 1u);

    sender.join();
    ::close(fds[0]);
    ::close(fds[1]);
}

// ── 3. Real 65536-byte block over TCP ───────────────────────────────────────

TEST(VortexSwarmP2PTest, FullBlockRoundTripOverTcp) {
    int srv = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(srv, 0);
    int opt = 1;
    ::setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(srv, 1), 0);
    socklen_t alen = sizeof(addr);
    ::getsockname(srv, reinterpret_cast<sockaddr*>(&addr), &alen);

    // A realistic 65536-byte block frame (VXC7 magic + deterministic body)
    std::vector<uint8_t> frame(65536, 0);
    const uint32_t magic = 0x58564337;
    std::memcpy(frame.data(), &magic, 4);
    for (size_t i = 4; i < frame.size(); ++i) frame[i] = static_cast<uint8_t>(i * 13 + 5);

    std::vector<uint8_t> received;
    std::thread acceptor([&]() {
        int c = ::accept(srv, nullptr, nullptr);
        ASSERT_GE(c, 0);
        vx::net::SwarmNode node;
        WireHeader hdr{};
        std::vector<uint8_t> payload;
        ASSERT_TRUE(node.recv_packet(c, hdr, payload));
        EXPECT_EQ(hdr.payload_len, 65536u);
        EXPECT_EQ(hdr.msg_type, static_cast<uint8_t>(WireMsgType::RAW_BLOCK_64K));
        received = std::move(payload);
        ::close(c);
    });

    int cfd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(cfd, 0);
    ASSERT_EQ(::connect(cfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    vx::net::SwarmNode sender_node;
    WireHeader hdr = vx::net::SwarmNode::make_header(
        WireMsgType::RAW_BLOCK_64K, 65536, 1);
    hdr.crc32c = vx::net::compute_wire_crc32c(frame.data(), frame.size());
    const uint64_t sent = sender_node.send_packet(cfd, hdr, frame.data());
    EXPECT_EQ(sent, 24u + 65536u);

    acceptor.join();
    ::close(cfd);
    ::close(srv);

    ASSERT_EQ(received.size(), 65536u);
    EXPECT_EQ(std::memcmp(received.data(), frame.data(), 65536), 0);
    EXPECT_EQ(sender_node.vx60_bytes_transferred(), 24u + 65536u);
}

// ── 4. Live split-brain reorg: 2 blocks vs 4 blocks -> converge at 4 ────────

TEST(VortexSwarmP2PTest, SplitBrainReorgConverges) {
    vx::net::SwarmNode node;
    const auto report = node.simulate_live_split_brain_reorg();

    EXPECT_TRUE(report.error.empty()) << report.error;
    EXPECT_EQ(report.node_a_height, 2u);
    EXPECT_EQ(report.node_b_height, 4u);
    EXPECT_GT(report.node_b_work, report.node_a_work);
    EXPECT_NE(report.node_a_tip_hex, report.node_b_tip_hex); // diverged tips
    EXPECT_EQ(report.blocks_rolled_back, 2u);                // O(1) undo.vxl rollback
    EXPECT_EQ(report.blocks_resynced, 4u);                   // RAW_BLOCK_64K resync
    EXPECT_TRUE(report.tip_hashes_match);
    EXPECT_EQ(report.final_height, 4u);
    EXPECT_EQ(report.final_tip_hex, report.node_b_tip_hex);
    EXPECT_TRUE(report.reorg_success);
    EXPECT_GT(report.vx60_bytes_transferred, 0u);
    EXPECT_GT(report.duration_us, 0u);
}

// ── 5. P2P listener relays a verified frame into the node-layer hook ───────

TEST(VortexSwarmP2PTest, ListenerRelaysVerifiedFrameToHook) {
    // Pick a free loopback port by binding an ephemeral listener first.
    int probe = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(probe, 0);
    int opt = 1;
    ::setsockopt(probe, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(probe, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    socklen_t alen = sizeof(addr);
    ::getsockname(probe, reinterpret_cast<sockaddr*>(&addr), &alen);
    const uint16_t port = ntohs(addr.sin_port);
    ::close(probe);

    // Receiver node: binds the VX60 listener and captures relayed frames.
    vx::net::SwarmNode receiver;
    std::atomic<int> frames_seen{0};
    std::vector<uint8_t> captured;
    std::mutex cap_mu;
    receiver.set_frame_hook([&](const uint8_t *frame, size_t len, const std::string &peer_label) {
        EXPECT_FALSE(peer_label.empty());
        if (len != 65536)
            return;
        std::lock_guard<std::mutex> lock(cap_mu);
        captured.assign(frame, frame + len);
        frames_seen.fetch_add(1);
    });
    ASSERT_TRUE(receiver.bind_p2p_listener(port));
    receiver.start();

    // Sender node: connects and broadcasts a deterministic 64 KiB frame.
    vx::net::SwarmNode sender;
    std::vector<uint8_t> frame(65536, 0);
    const uint32_t magic = 0x58564337; // VXC7 block magic
    std::memcpy(frame.data(), &magic, 4);
    for (size_t i = 4; i < frame.size(); ++i) frame[i] = static_cast<uint8_t>(i * 31 + 7);
    ASSERT_TRUE(sender.connect_peer_tcp("127.0.0.1", port));
    sender.broadcast_frame(std::span<const uint8_t, 65536>(frame.data(), frame.size()));

    // The hook must fire within a bounded window (listener thread path).
    for (int i = 0; i < 100 && frames_seen.load() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

    receiver.emergency_stop();
    EXPECT_EQ(frames_seen.load(), 1);
    ASSERT_EQ(captured.size(), 65536u);
    EXPECT_EQ(std::memcmp(captured.data(), frame.data(), 65536), 0);
}

// ── 7. Withhold escalation to ban (BACKLOG 2.11 third checkbox) ─────────────

TEST(VortexSwarmP2PTest, WithholdEscalatesToBan) {
    // Free port probe: bind port 0, read the assigned port, close.
    int probe = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(probe, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(probe, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)), 0);
    socklen_t alen = sizeof(addr);
    ::getsockname(probe, reinterpret_cast<sockaddr *>(&addr), &alen);
    const uint16_t port = ntohs(addr.sin_port);
    ::close(probe);

    vx::net::SwarmNode receiver;
    ASSERT_TRUE(receiver.bind_p2p_listener(port));
    receiver.start();

    // A client that PINGs gets promoted into the peer table (that is what
    // makes report_withhold scoring possible at all: the score lives on the
    // PeerInfo entry).
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::connect(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)), 0);
    socklen_t clen = sizeof(sa);
    ::getsockname(fd, reinterpret_cast<sockaddr *>(&sa), &clen);
    const std::string label = "127.0.0.1:" + std::to_string(ntohs(sa.sin_port));

    WireHeader ping = vx::net::SwarmNode::make_header(WireMsgType::PING, 0, 77);
    ping.crc32c = vx::net::compute_wire_crc32c(nullptr, 0);
    ASSERT_EQ(::send(fd, &ping, sizeof(ping), 0), static_cast<ssize_t>(sizeof(ping)));

    // The PONG proves the reader thread processed the PING (and promoted us).
    bool got_pong = false;
    for (int i = 0; i < 100 && !got_pong; ++i) {
        WireHeader h{};
        ssize_t n = ::recv(fd, &h, sizeof(h), MSG_DONTWAIT);
        if (n != static_cast<ssize_t>(sizeof(h))) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        if (h.msg_type == static_cast<uint8_t>(WireMsgType::PONG))
            got_pong = true;
    }
    ASSERT_TRUE(got_pong) << "peer was never promoted; the escalation test is vacuous";
    EXPECT_FALSE(receiver.peer_is_banned(label));

    // Three withhold strikes (34 each) cross the >=100 ban threshold.
    receiver.report_withhold(label, 34);
    EXPECT_FALSE(receiver.peer_is_banned(label));
    receiver.report_withhold(label, 34);
    EXPECT_FALSE(receiver.peer_is_banned(label));
    receiver.report_withhold(label, 34);
    EXPECT_TRUE(receiver.peer_is_banned(label));

    receiver.emergency_stop();
    ::close(fd);
}

// ── 8. Outbound dial fires the connect callback WITHOUT deadlocking ────────
// (security review P0-1, 2.11 third checkbox: the retention serve re-enters
// peers_mutex_ and takes state_mutex_ first, so the callback must fire
// outside both locks on the dialing path too - the pre-fix code held
// peers_mutex_ while firing and froze the whole node on the first dial).

TEST(VortexSwarmP2PTest, OutboundDialFiresConnectedCallback) {
    int probe = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(probe, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(probe, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)), 0);
    socklen_t alen = sizeof(addr);
    ::getsockname(probe, reinterpret_cast<sockaddr *>(&addr), &alen);
    const uint16_t port = ntohs(addr.sin_port);
    ::close(probe);

    vx::net::SwarmNode listener; // no callbacks: plain receiver
    ASSERT_TRUE(listener.bind_p2p_listener(port));
    listener.start();

    // The DIALING node carries the connect callback (as HttpServer does
    // once the retention wiring is installed). Pre-fix this call sequence
    // self-deadlocked the dialing thread under peers_mutex_.
    vx::net::SwarmNode dialer;
    std::atomic<int> connects{0};
    std::string seen_label;
    dialer.set_peer_connected_callback([&](const std::string &label) {
        seen_label = label;
        connects.fetch_add(1);
    });
    ASSERT_TRUE(dialer.connect_peer_tcp("127.0.0.1", port));

    for (int i = 0; i < 50 && connects.load() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

    EXPECT_EQ(connects.load(), 1) << "callback must fire exactly once per dial";
    EXPECT_EQ(seen_label, "127.0.0.1:" + std::to_string(port));

    dialer.emergency_stop();
    listener.emergency_stop();
}

// ── 9. P0 GATE: GET_CERTS round-trip returns the full verified cert ────────
// A node that missed a relayed certificate pulls it by deterministic id and
// must receive the FULL record (2490-byte ROLLOVER_CERT payload), which the
// puller re-verifies exactly like a relayed one.

TEST(VortexSwarmP2PTest, GetCertsRoundTripReturnsFullCert) {
    // The registry is a process-global singleton; registering the honest
    // cert here is what the serving node answers from.
    const auto cert = make_valid_cert("VX_P2P_GCR_V1");
    ASSERT_TRUE(vx::crypto::pq::PqWitnessRegistry::instance().register_rollover_cert(cert));
    const auto id = vx::crypto::pq::rollover_cert_id(cert);

    const uint16_t port = free_tcp_port();
    vx::net::SwarmNode server;
    ASSERT_TRUE(server.bind_p2p_listener(port));
    server.start();

    int fd = connect_client(port);

    std::vector<uint8_t> payload(4 + 32);
    const uint32_t count = 1;
    std::memcpy(payload.data(), &count, 4);
    std::memcpy(payload.data() + 4, id.data(), 32);
    ASSERT_TRUE(send_packet(fd, WireMsgType::GET_CERTS, payload));

    WireHeader h{};
    std::vector<uint8_t> got;
    ASSERT_TRUE(read_packet(fd, h, got)) << "no GET_CERTS response";
    EXPECT_EQ(h.msg_type, static_cast<uint8_t>(WireMsgType::ROLLOVER_CERT));
    ASSERT_EQ(got.size(), 42u + 4u + 4u + 32u + 32u + sizeof(vx::crypto::pq::PqSignatureWitness));
    // Decode the way handle_rollover_cert_payload would and compare fields.
    EXPECT_EQ(std::memcmp(got.data(), cert.sender.data(), 42), 0);
    uint32_t from_w = 0, to_w = 0;
    std::memcpy(&from_w, got.data() + 42, 4);
    std::memcpy(&to_w, got.data() + 46, 4);
    EXPECT_EQ(from_w, cert.from_window);
    EXPECT_EQ(to_w, cert.to_window);
    EXPECT_EQ(std::memcmp(got.data() + 50, cert.old_root.data(), 32), 0);
    EXPECT_EQ(std::memcmp(got.data() + 82, cert.new_root.data(), 32), 0);

    // An unknown id must answer NOTHING (no error channel).
    std::array<uint8_t, 32> bogus{};
    bogus.fill(0x5A);
    std::vector<uint8_t> bogus_payload(4 + 32);
    std::memcpy(bogus_payload.data(), &count, 4);
    std::memcpy(bogus_payload.data() + 4, bogus.data(), 32);
    ASSERT_TRUE(send_packet(fd, WireMsgType::GET_CERTS, bogus_payload));
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // settle: let any wrong reply land
    char probe = 0;
    const ssize_t rn = ::recv(fd, &probe, 1, MSG_DONTWAIT);
    EXPECT_TRUE(rn <= 0) << "unknown id must stay silent";

    server.emergency_stop();
    ::close(fd);
}

// ── 10. P0 GATE: CERT_INV with an unknown id pulls via GET_CERTS ───────────
// The reverse direction: a peer announcing an id this node does not hold
// makes this node ask for it by id (the missing-cert detection path).

TEST(VortexSwarmP2PTest, CertInvUnknownIdTriggersGetCerts) {
    const uint16_t port = free_tcp_port();
    vx::net::SwarmNode server;
    ASSERT_TRUE(server.bind_p2p_listener(port));
    server.start();

    int fd = connect_client(port);

    std::array<uint8_t, 32> unknown{};
    unknown.fill(0x77);
    std::vector<uint8_t> payload(4 + 32);
    const uint32_t count = 1;
    std::memcpy(payload.data(), &count, 4);
    std::memcpy(payload.data() + 4, unknown.data(), 32);
    ASSERT_TRUE(send_packet(fd, WireMsgType::CERT_INV, payload));

    WireHeader h{};
    std::vector<uint8_t> got;
    ASSERT_TRUE(read_packet(fd, h, got)) << "no GET_CERTS pull for the unknown id";
    EXPECT_EQ(h.msg_type, static_cast<uint8_t>(WireMsgType::GET_CERTS));
    ASSERT_EQ(got.size(), 4u + 32u);
    uint32_t rcount = 0;
    std::memcpy(&rcount, got.data(), 4);
    EXPECT_EQ(rcount, 1u);
    EXPECT_EQ(std::memcmp(got.data() + 4, unknown.data(), 32), 0);

    // A CERT_INV whose ids are ALL known must answer nothing.
    const auto cert = make_valid_cert("VX_P2P_CIUK_V1");
    ASSERT_TRUE(vx::crypto::pq::PqWitnessRegistry::instance().register_rollover_cert(cert));
    const auto known = vx::crypto::pq::rollover_cert_id(cert);
    std::vector<uint8_t> known_payload(4 + 32);
    std::memcpy(known_payload.data(), &count, 4);
    std::memcpy(known_payload.data() + 4, known.data(), 32);
    ASSERT_TRUE(send_packet(fd, WireMsgType::CERT_INV, known_payload));
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // settle
    std::array<uint8_t, 1> probe{};
    const ssize_t rn = ::recv(fd, probe.data(), 1, MSG_DONTWAIT);
    EXPECT_TRUE(rn <= 0) << "all-known CERT_INV must stay silent";

    server.emergency_stop();
    ::close(fd);
}

// ── 11. P0 GATE: oversized id lists fail closed, no response, no crash ─────

TEST(VortexSwarmP2PTest, OversizedCertListRefused) {
    const uint16_t port = free_tcp_port();
    vx::net::SwarmNode server;
    ASSERT_TRUE(server.bind_p2p_listener(port));
    server.start();

    int fd = connect_client(port);

    // count = 65 breaks the wire bound (payload 4 + 65*32 = 2124 bytes).
    std::vector<uint8_t> big(4 + 65 * 32, 0xAB);
    const uint32_t count = 65;
    std::memcpy(big.data(), &count, 4);
    ASSERT_TRUE(send_packet(fd, WireMsgType::GET_CERTS, big));
    ASSERT_TRUE(send_packet(fd, WireMsgType::CERT_INV, big));

    // The connection must survive (corruption-free drop, not a kill) and
    // answer NOTHING to either oversized request.
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // settle
    std::array<uint8_t, 1> probe{};
    const ssize_t rn = ::recv(fd, probe.data(), 1, MSG_DONTWAIT);
    EXPECT_TRUE(rn <= 0) << "oversized list must stay silent";
    // Liveness: a well-formed PING after the abuse still gets its PONG.
    WireHeader ping = vx::net::SwarmNode::make_header(WireMsgType::PING, 0, 42);
    ping.crc32c = vx::net::compute_wire_crc32c(nullptr, 0);
    ASSERT_EQ(::send(fd, &ping, sizeof(ping), 0), static_cast<ssize_t>(sizeof(ping)));
    bool got_pong = false;
    for (int i = 0; i < 100 && !got_pong; ++i) {
        WireHeader h{};
        ssize_t n = ::recv(fd, &h, sizeof(h), MSG_DONTWAIT);
        if (n != static_cast<ssize_t>(sizeof(h))) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        if (h.msg_type == static_cast<uint8_t>(WireMsgType::PONG))
            got_pong = true;
    }
    EXPECT_TRUE(got_pong) << "connection must survive oversized id lists";

    server.emergency_stop();
    ::close(fd);
}
