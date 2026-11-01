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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

namespace {

// VX60 helpers mirroring the wire helpers under test.
using vx::net::WireHeader;
using vx::net::WireMsgType;
using vx::net::VX60_MAGIC;

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

    // A realistic 65536-byte block frame (VXC6 magic + deterministic body)
    std::vector<uint8_t> frame(65536, 0);
    const uint32_t magic = 0x58564336;
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
    receiver.set_frame_hook([&](const uint8_t* frame, size_t len) {
        if (len != 65536) return;
        std::lock_guard<std::mutex> lock(cap_mu);
        captured.assign(frame, frame + len);
        frames_seen.fetch_add(1);
    });
    ASSERT_TRUE(receiver.bind_p2p_listener(port));
    receiver.start();

    // Sender node: connects and broadcasts a deterministic 64 KiB frame.
    vx::net::SwarmNode sender;
    std::vector<uint8_t> frame(65536, 0);
    const uint32_t magic = 0x58564336; // VXC6 block magic
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
