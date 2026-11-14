// VortexSponge256 on CUDA — the real GPU port of the consensus hash
// (docs/design source of truth: include/vx/blockchain/crypto_sponge.hpp).
//
// BIT-EXACT PARITY RULE (no-stub rule, owner directive 2026-11-14): the
// kernel below must produce byte-identical digests with the CPU sponge
// for every input, or the track does not ship. tests/test_cuda_parity
// pins this over thousands of random vectors INCLUDING full 64 KiB
// block frames (the PoGW hashing shape) before anything GPU-produced is
// allowed near a verification path.
//
// Device workhorse: 12 rounds x 4 ChaCha-style ARX quarter-rounds over
// an 8x uint64 state with the Golden-Phi init — pure ALU, no memory
// traffic inside the permutation, no shared memory needed, one thread
// per message.
//
// Benchmarks: gpu/bench_sponge (standalone; reports GB/s including and
// excluding the PCIe transfer — both numbers are honest numbers).
#pragma once

#include <cuda_runtime.h>

#include <cstdint>
#include <cstddef>

namespace vx::gpu {

// Hashes `n` independent messages with VortexSponge256 on the device.
// msgs: n buffers back to back; lens: n message lengths (bytes);
// digests_out: n x 32 bytes, VortexSponge256-computed digests.
// Single stream, synchronous with the host when stream == 0.
// Returns cudaSuccess or the first CUDA error (fail-closed parity rule:
// a failed launch must never be reported as "hashed").
cudaError_t sponge256_batch(const uint8_t *msgs, const uint32_t *lens, uint32_t n,
                            uint8_t *digests_out, cudaStream_t stream = 0);

// Best-effort device capability report for the bench/log line.
// Returns false when no CUDA device is available.
bool device_info(int *device_id, char *name_out, int name_len, int *sm_count);

} // namespace vx::gpu
