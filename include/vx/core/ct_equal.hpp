#pragma once

#include <cstddef>
#include <cstdint>

namespace vx::core {

// Constant-time equality for byte strings of equal declared length: the
// loop always runs over the full range and folds every byte difference
// into one accumulator, so the comparison time carries no information
// about where (or whether) the inputs differ. Math-audit F8: digest and
// tag comparisons across the crypto layer route through this helper.
inline bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) noexcept {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

} // namespace vx::core
