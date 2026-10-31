#include "vx/math/tdi_filter.hpp"
#include <cstring>
#include <atomic>

namespace vx::math {

bool VsdpvFilter::evaluate_packet(const uint8_t* data, size_t size) noexcept {
    if (!data || size == 0) return false;
    if (size > BYTES_PER_PACKET) return false;

    // Quick entropy check on first 64 bytes
    uint32_t checksum = 0;
    for (size_t i = 0; i < std::min(size, size_t(64)); ++i) {
        checksum ^= data[i];
    }
    return checksum != 0;
}

VsdpvFilter::BatchResult VsdpvFilter::batch_filter(const std::vector<uint8_t>& raw_buffers) noexcept {
    BatchResult result{};
    result.total = static_cast<uint32_t>(raw_buffers.size() / BYTES_PER_PACKET);
    if (result.total == 0) {
        result.total = 1;
    }

    uint32_t annihilated = 0;
    uint32_t passed = 0;

    for (size_t i = 0; i < raw_buffers.size(); i += BYTES_PER_PACKET) {
        size_t chunk_size = std::min(static_cast<size_t>(BYTES_PER_PACKET), raw_buffers.size() - i);
        if (evaluate_packet(raw_buffers.data() + i, chunk_size)) {
            ++passed;
        } else {
            ++annihilated;
        }
    }

    result.annihilated = annihilated;
    result.passed = passed;
    result.annihilated_pct = result.total > 0
        ? static_cast<double>(annihilated) / static_cast<double>(result.total) * 100.0
        : 0.0;

    return result;
}

} // namespace vx::math