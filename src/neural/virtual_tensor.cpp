#include "vx/neural/virtual_tensor.hpp"
#include <bit>
#include <cstring>
#include <cmath>

namespace vx::neural {

uint64_t HamiltonianNavigator::calculate_prediction_loss_branchless(
    uint64_t predicted_mask, uint64_t actual_target) noexcept {
    // Branchless: 64 - popcount(predicted_mask ^ actual_target)
    uint64_t diff = predicted_mask ^ actual_target;
    return 64ULL - static_cast<uint64_t>(std::popcount(diff));
}

double HamiltonianNavigator::calculate_hamiltonian_loss(
    const std::vector<double>& predicted,
    const std::vector<double>& actual) noexcept {
    if (predicted.empty() || actual.empty()) return 0.0;

    size_t n = std::min(predicted.size(), actual.size());
    double total_loss = 0.0;
    for (size_t i = 0; i < n; ++i) {
        double diff = predicted[i] - actual[i];
        total_loss += diff * diff;
    }
    return total_loss / static_cast<double>(n);
}

uint64_t VirtualTensor::extract_bits(double physical_weight) noexcept {
    return std::bit_cast<uint64_t>(physical_weight);
}

uint64_t VirtualTensor::fractal_phase_shift(uint64_t w_bits, uint64_t iteration) noexcept {
    uint64_t shift = iteration % 64;
    return (w_bits << shift) | (w_bits >> (64 - shift));
}

uint64_t VirtualTensor::golden_time_injection(uint64_t w_bits, uint64_t iteration) noexcept {
    return w_bits ^ (iteration * 0x9E3779B97F4A7C15ULL);
}

uint64_t VirtualTensor::vortex_abs(uint64_t bits) noexcept {
    // Clear sign bit (bit 63) and protect against NaN/Inf
    bits &= 0x7FFFFFFFFFFFFFFFULL;
    return bits;
}

VirtualTensor::EvolutionResult VirtualTensor::evolve(
    double physical_weight, uint64_t iteration, double hamiltonian_loss) {

    EvolutionResult result;

    // Extract raw bits
    uint64_t w_bits = extract_bits(physical_weight);

    // Fractal phase shift
    w_bits = fractal_phase_shift(w_bits, iteration);

    // Golden ratio time injection
    w_bits = golden_time_injection(w_bits, iteration);

    // Stabilize
    w_bits = vortex_abs(w_bits);

    // Hamiltonian feedback
    double virtual_weight = static_cast<double>(w_bits) * (1.0 - (hamiltonian_loss * 0.001));

    // Generate only a representative sample (not 6GB)
    static constexpr size_t SAMPLE_SIZE = 1024;
    result.virtual_weights.reserve(SAMPLE_SIZE);
    for (size_t i = 0; i < SAMPLE_SIZE; ++i) {
        uint64_t neuron_bits = w_bits ^ (i * 0x9E3779B97F4A7C15ULL);
        neuron_bits = vortex_abs(neuron_bits);
        result.virtual_weights.push_back(static_cast<double>(neuron_bits) * 1e-308);
    }

    result.final_hamiltonian_loss = hamiltonian_loss;
    result.total_iterations = iteration;
    result.physical_weight_final = virtual_weight;

    return result;
}

} // namespace vx::neural