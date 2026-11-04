// -----------------------------------------------------------------------------
// libFuzzer target: VX60 wire ingest, from the plausibility gate down to the
// frame-ingestion entry the node layer uses -- no sockets anywhere.
//
// Every input deterministically builds a full 24-byte WireHeader with a REAL
// CRC32C over its payload (so the receiver's CRC gate passes and the deeper
// dispatch layers are reached), plus a payload shaped by msg_type:
//
//   RAW_BLOCK_64K  -> a 65536-byte frame (BlockBuilder-built with a real
//                     merkle root, or hostile raw bytes) handed to
//                     SwarmNode::handle_incoming_frame with a production-
//                     style frame hook: tip check -> validate_block ->
//                     ledger apply, the same shape the RPC node layer's
//                     apply_remote_frame runs against a genesis-only chain.
//   PQ_WITNESS     -> the 2450-byte digest|sender|witness record through the
//                     peer-reader slice: PqWitnessRegistry::
//                     register_witness_bytes. Hostile bytes reject cheaply
//                     (witness commitment first); the deep mode signs a real
//                     witness so the full WOTS+/XMSS chain and the
//                     consensus lookup (lookup_verifying) are exercised.
//   TX_COCOON_112B -> a 128-byte Dandelion++ cocoon through
//                     relay_cocoon_step / open_cocoon / seal_cocoon.
//   other types    -> the plausibility + CRC fast paths and the drop path
//                     (production closes the connection on unexpected
//                     types; PONG is a keepalive no-op).
//
// Header corruption and CRC-flip control bits keep the fast-path rejections
// live: an implausible header kills the connection before any payload is
// read, and a CRC mismatch drops the packet without killing the connection.
//
// Invariant: any byte sequence is accepted or rejected without crashing,
// hanging or reading out of bounds -- this is the first code a remote peer's
// packet touches.
// -----------------------------------------------------------------------------
#include "harness_util.hpp"
#include "vx/net/swarm_node.hpp"

#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace {

using vxfuzz::anchor;
using vxfuzz::BitStream;
using vxfuzz::ChainAnchor;
using vx::blockchain::BlockBuilder;
using vx::blockchain::BlockFrame;
using vx::blockchain::BlockView;
using vx::blockchain::Transaction;
using vx::net::WireHeader;

// Production-shape frame hook (mirrors HttpServer::apply_remote_frame minus
// disk state): only a tip-extending frame is judged; the single intake gate
// runs with the real chain context (genesis tip hash + timestamp, wall
// clock); a gate pass is applied to a fresh genesis-seeded ledger so the
// state layer's authorization rules sit behind the wire path too. Every
// rejection reason here is live: hostile height, hostile prev hash, hostile
// timestamp, insufficient work and state-layer refusals all diverge.
void frame_intake_hook(const uint8_t* frame, size_t len) {
    if (len != vx::blockchain::BLOCK_SIZE_BYTES) return;
    const ChainAnchor& a = anchor();
    vx::blockchain::BlockView view{
        std::span<const uint8_t, 65536>(frame, len)};
    const uint64_t next_height = 1; // genesis-only chain: tip + 1
    if (view.header().block_height != next_height) return;
    if (std::memcmp(a.tip_hash, view.header().prev_block_hash, 32) != 0) return;

    vxfuzz::GateOpts o;
    o.expected_height = next_height;
    o.expected_prev = a.tip_hash;
    o.prev_timestamp = a.genesis_ts;
    o.now_unix = static_cast<uint64_t>(std::time(nullptr));
    o.difficulty_bits = 0;
    const auto* raw = reinterpret_cast<const vx::blockchain::RawBlock*>(frame);
    if (!vxfuzz::validate_with_ctx(*raw, o)) {
        return;
    }
    vx::state::LedgerState ledger;
    if (!vxfuzz::apply_genesis(ledger)) return;
    BlockFrame f;
    std::memcpy(f.data(), frame, vx::blockchain::BLOCK_SIZE_BYTES);
    (void)ledger.apply_block(BlockView(f));
}

// Builds the deep (real-signature) PQ_WITNESS payload: 32B digest || 42B
// sender || 2376B witness, exactly the record the peer reader slices.
void build_real_witness_payload(std::vector<uint8_t>& payload, BitStream& bs,
                                vx::blockchain::Transaction& out_tx) {
    uint8_t tag[16];
    bs.bytes(tag, sizeof(tag));
    const vxfuzz::PqAccount acc = vxfuzz::make_pq_account(tag, sizeof(tag));

    Transaction tx{};
    std::memcpy(tx.sender_nfa, acc.addr.data(), 42);
    for (int i = 0; i < 42; ++i) tx.receiver_nfa[i] = bs.u8();
    vx::blockchain::tx_set_amount(tx, bs.u64());
    vx::blockchain::tx_set_fee(tx, bs.u32());
    vx::blockchain::tx_set_nonce(tx, bs.u32());
    // pq_sign_transaction derives the SegPQ anchor (cocoon_proof) itself.
    vx::crypto::pq::PqSignatureWitness w;
    if (vxfuzz::pq_sign(tx, acc.sk)) {
        const auto digest = vx::crypto::pq::tx_msg_digest(tx);
        std::memcpy(payload.data(), digest.data(), 32);
        std::memcpy(payload.data() + 32, tx.sender_nfa, 42);
        std::memcpy(payload.data() + 74, &w, sizeof(w));
        out_tx = tx;
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 16) return 0;
    BitStream bs(data, size);

    const uint8_t ctrl = bs.u8();
    const uint8_t type_sel = static_cast<uint8_t>(bs.u8() % 10); // 0 stays implausible
    const uint8_t flags = bs.u8();
    const uint64_t peer_nonce = bs.u64();
    // PoGW comparator difficulty: input-driven, hard-capped at 26 leading
    // zero bits (33 picks 0..32; above 26 the comparator call itself stays
    // one sponge pass, but the cap documents the harness ceiling).
    uint64_t pogw_bits = bs.u8() % 33;
    if (pogw_bits > 26) pogw_bits = 26;

    const bool hostile_payload = (ctrl & 0x01) != 0;
    const bool raw_ts = (ctrl & 0x02) != 0;
    const bool corrupt_header = (ctrl & 0x04) != 0;
    const bool corrupt_crc = (ctrl & 0x08) != 0;
    const bool nonzero_reserved = (ctrl & 0x10) != 0;
    const bool consistent_frame = (ctrl & 0x20) != 0;
    const bool deep = (ctrl & 0xE0) == 0xC0; // 1-in-8: deep modes sign real
                                             // WOTS+/XMSS keys (~20 ms per sign)

    const ChainAnchor& a = anchor();
    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    std::vector<uint8_t> payload;
    // Transaction kept alive for the PQ consensus lookup after registration.
    vx::blockchain::Transaction witness_tx{};

    switch (type_sel) {
    case 0x04: { // RAW_BLOCK_64K: dispatch requires exactly 65536 payload bytes
        payload.assign(vx::blockchain::BLOCK_SIZE_BYTES, 0);
        if (hostile_payload) {
            bs.bytes(payload.data(), payload.size());
        } else {
            BlockBuilder b;
            // Chain position: consistent mode mirrors what a real producer
            // puts in a frame (tip + 1, prev = tip); every other value comes
            // straight from the input.
            const uint64_t height = consistent_frame ? 1 : bs.u64();
            b.set_height(height);
            uint8_t prev[32];
            if (consistent_frame) {
                std::memcpy(prev, a.tip_hash, 32);
            } else {
                bs.bytes(prev, 32);
            }
            b.set_prev_hash(prev);
            uint64_t ts = bs.u64();
            if (!raw_ts && ts < a.genesis_ts) ts = a.genesis_ts + (ts % 64);
            if (!raw_ts && ts > now) ts = now;
            b.set_timestamp(ts);
            std::array<uint8_t, 384> coords{};
            b.set_attractor_coords(coords.data());
            const uint32_t ntx = bs.u8() % (vx::blockchain::MAX_TX_PER_BLOCK + 1);
            for (uint32_t i = 0; i < ntx; ++i) {
                (void)b.add_transaction(vxfuzz::decode_tx(bs));
            }
            b.finalize(); // real merkle root over the body
            std::memcpy(payload.data(), b.bytes().data(), vx::blockchain::BLOCK_SIZE_BYTES);
        }
        // Work comparator, one full-frame pass per input.
        (void)vx::blockchain::pogw_meets_target(payload.data(), pogw_bits);
        break;
    }
    case 0x09: { // PQ_WITNESS: 32 + 42 + 2376 = 2450 bytes
        payload.assign(74 + sizeof(vx::crypto::pq::PqSignatureWitness), 0);
        if (deep) {
            build_real_witness_payload(payload, bs, witness_tx);
        } else {
            bs.bytes(payload.data(), payload.size());
        }
        break;
    }
    case 0x05: { // TX_COCOON_112B: 128-byte Dandelion++ cocoon
        payload.assign(sizeof(vx::net::TxCocoon), 0);
        if (deep) {
            // Real cocoon around an input-shaped transaction: true CRC field,
            // input-driven TDI score and phase.
            Transaction tx{};
            for (int i = 0; i < 42; ++i) tx.sender_nfa[i] = bs.u8();
            for (int i = 0; i < 42; ++i) tx.receiver_nfa[i] = bs.u8();
            vx::blockchain::tx_set_amount(tx, bs.u64());
            vx::blockchain::tx_set_fee(tx, bs.u32());
            vx::blockchain::tx_set_nonce(tx, bs.u32());
            const uint16_t tdi_fp = static_cast<uint16_t>(bs.u8() | (bs.u8() << 8));
            const auto c = vx::net::SwarmNode::seal_cocoon(tx, tdi_fp);
            std::memcpy(payload.data(), &c, sizeof(c));
        } else {
            bs.bytes(payload.data(), payload.size());
            // Repair the CRC field to its true value so the integrity gate
            // passes and the TDI / phase / hop logic behind it is reached.
            auto* c = reinterpret_cast<vx::net::TxCocoon*>(payload.data());
            c->cocoon_crc32c = vx::net::compute_wire_crc32c(c->encrypted_tx, 112);
        }
        break;
    }
    default: { // HANDSHAKE / INV / GET_BLOCK / PING / PONG / GQC_VOTE
        const uint32_t len = bs.u32() % 65537u;
        payload.assign(len, 0);
        bs.bytes(payload.data(), len);
        break;
    }
    }

    WireHeader h{};
    h.magic = vx::net::VX60_MAGIC;
    h.msg_type = type_sel;
    h.flags = flags;
    h.reserved = nonzero_reserved ? static_cast<uint16_t>(bs.u8() | 1) : 0;
    h.payload_len = static_cast<uint32_t>(payload.size());
    h.crc32c = vx::net::compute_wire_crc32c(
        payload.empty() ? nullptr : payload.data(), payload.size());
    h.peer_nonce = peer_nonce;

    if (corrupt_header) {
        switch (bs.u8() % 5) {
        case 0: h.magic ^= 0xFFu; break;
        case 1: h.msg_type = 0x00; break; // below the 0x01..0x09 window
        case 2: h.msg_type = 0x0A; break; // above it
        case 3: h.reserved = 1; break;
        default: h.payload_len = 70000; break; // above the 65536 bound
        }
    }
    if (corrupt_crc) h.crc32c ^= 1u;

    // recv_packet fast paths, mirrored socket-free: an implausible header
    // kills the connection before any payload allocation; a CRC mismatch
    // drops the packet but keeps the connection.
    if (!vx::net::wire_header_plausible(h)) return 0;
    if (vx::net::compute_wire_crc32c(
            payload.empty() ? nullptr : payload.data(), payload.size()) != h.crc32c) {
        return 0;
    }

    // Peer dispatch, mirroring peer_reader_loop / serve_connection. A local
    // node per input: no listener threads are started, so construction and
    // teardown are pure bookkeeping.
    vx::net::SwarmNode node;
    std::string label;
    const size_t lbl_len = 1 + (bs.u8() % 16);
    for (size_t i = 0; i < lbl_len; ++i) {
        label.push_back(static_cast<char>('a' + (bs.u8() % 26)));
    }

    const auto type = static_cast<vx::net::WireMsgType>(h.msg_type);
    if (type == vx::net::WireMsgType::PONG) return 0; // keepalive no-op

    if (type == vx::net::WireMsgType::RAW_BLOCK_64K && payload.size() == 65536) {
        const std::span<const uint8_t, 65536> frame(payload.data(), payload.size());
        node.set_frame_hook(frame_intake_hook);
        node.handle_incoming_frame(label, frame);
        // The node layer relays witnesses for the frame's user transactions.
        node.broadcast_witnesses_for(frame);
        return 0;
    }

    if (type == vx::net::WireMsgType::PQ_WITNESS &&
        payload.size() == 74 + sizeof(vx::crypto::pq::PqSignatureWitness)) {
        // The exact slice peer_reader_loop runs on a WITNESS record.
        vx::crypto::pq::PqSignatureWitness w;
        std::memcpy(&w, payload.data() + 74, sizeof(w));
        std::array<uint8_t, 32> digest{};
        std::memcpy(digest.data(), payload.data(), 32);
        (void)vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
            digest, payload.data() + 32, w);
        // Consensus lookup: the registered candidate must verify against the
        // transaction the digest was derived from (deep mode) or against a
        // hostile digest (raw mode).
        vx::crypto::pq::PqSignatureWitness out{};
        (void)vx::crypto::pq::PqWitnessRegistry::instance().lookup_verifying(
            witness_tx, out);
        return 0;
    }

    if (type == vx::net::WireMsgType::TX_COCOON_112B && payload.size() == 128) {
        vx::net::TxCocoon c{};
        std::memcpy(&c, payload.data(), sizeof(c));
        vx::net::CocoonHopTrace trace;
        for (int hop = 0; hop < 9; ++hop) {
            if (!node.relay_cocoon_step(c, trace)) break;
        }
        (void)vx::net::SwarmNode::open_cocoon(c);
        return 0;
    }

    return 0; // unexpected message type: production drops the connection
}
