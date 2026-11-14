// CPU-side reference bench for the CUDA track (see bench_sponge.cu).
// Compiled with the C++26 host compiler — the .cu translation unit must
// not include block.hpp (C++26 constructs nvcc cannot parse).
#pragma once
#include <cstdint>

namespace vx::gpu {
// Runs `frames` single-threaded VortexSponge256 hashes over packed 64 KiB
// frames; returns the per-frame wall time in milliseconds and folds every
// digest byte into `checksum` — the fold keeps the whole loop observable,
// so the optimizer cannot dead-code it into a 0.0000 ms lie.
double sponge256_cpu_bench_ms(const uint8_t *packed, uint32_t frames, uint32_t frame_len,
                              uint64_t &checksum);
} // namespace vx::gpu
