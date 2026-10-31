#pragma once

#include <cstdint>
#include <string>
#include <numeric>
#include <vector>
#include <atomic>

namespace vx::math {

struct TdiEvaluation {
    double tdi;
    bool isAnnihilated;
    std::string reason;
};

// Vortex Strict Dynamic Payload Validation (VSDPV) DoS Filter
class VsdpvFilter {
public:
    static constexpr uint32_t MAX_PACKETS_PER_BURST = 100000;
    static constexpr uint32_t BYTES_PER_PACKET = 1500; // MTU

    struct BatchResult {
        uint32_t total;
        uint32_t annihilated;
        uint32_t passed;
        double annihilated_pct;
    };

    // Batch SIMD/OpenMP express filter on raw network buffers
    static BatchResult batch_filter(const std::vector<uint8_t>& raw_buffers) noexcept;

    // Single packet evaluation
    static bool evaluate_packet(const uint8_t* data, size_t size) noexcept;
};

class TdiFilter {
public:
    static constexpr double MIN_THRESHOLD = 1.0;
    static constexpr uint32_t MAX_SIZE_BYTES = 100000; // 100 KB limit for standard mempool

    /**
     * @brief Computes Transaction Density Index: (Amount / Size) * 10000
     */
    static TdiEvaluation evaluate(uint32_t sizeBytes, double amountVx) noexcept {
        if (sizeBytes == 0) {
            return TdiEvaluation{ .tdi = 0.0, .isAnnihilated = true, .reason = "Null byte packet size" };
        }
        if (sizeBytes > MAX_SIZE_BYTES) {
            return TdiEvaluation{ .tdi = 0.0, .isAnnihilated = true, .reason = "Payload exceeds maximum 100KB limit" };
        }
        if (amountVx <= 0.0) {
            return TdiEvaluation{ .tdi = 0.0, .isAnnihilated = true, .reason = "Non-positive transaction transfer amount" };
        }

        double density = (amountVx / static_cast<double>(sizeBytes)) * 10000.0;
        bool drop = density < MIN_THRESHOLD;

        return TdiEvaluation{
            .tdi = density,
            .isAnnihilated = drop,
            .reason = drop ? "Transaction density falls below critical economic threshold (dust attack)" : "Valid"
        };
    }
};

} // namespace vx::math
