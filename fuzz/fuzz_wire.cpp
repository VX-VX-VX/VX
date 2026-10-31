// libFuzzer target: VX60 wire header + payload ingest path.
//
// Invariant: the plausibility gate and the CRC32C computation must accept
// or reject any byte sequence without crashing or reading out of bounds —
// this is the first code a remote peer's packet touches.
#include "vx/net/swarm_node.hpp"

#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using vx::net::WireHeader;

    if (size < sizeof(WireHeader)) return 0;

    WireHeader h{};
    std::memcpy(&h, data, sizeof(h));

    std::vector<uint8_t> payload(data + sizeof(WireHeader), data + size);

    const bool plausible = vx::net::wire_header_plausible(h);
    const uint32_t crc = vx::net::compute_wire_crc32c(payload.data(), payload.size());
    // The full receiver gate: a plausible header must also carry a matching
    // CRC over its declared-length payload to pass ingestion.
    const bool accepted = plausible && (h.crc32c == crc);
    (void)accepted;
    return 0;
}
