// Vortex 1024-bit Solinas field on CUDA (CUDA track deliverable 2,
// 2026-11-14). GPU port of the Galois attractor's modular arithmetic —
// the same field the CPU core computes with GMP over the proven CRT
// moduli (AttractorModuli::secure_crt):
//   p = 2^1024 - 2^64  - 1747
//   q = 2^1024 - 2^888 - 3943
//   r = 2^1024 - 2^512 - 267799
//
// NO-STUB PARITY RULE: the kernel must return bit-identical results with
// GMP `(a*b) % N` on every input, or the track does not ship —
// tests/test_cuda_field_parity pins this over thousands of random pairs
// per modulus, including multiplication chains (the pow3 shape the
// attractor's cubic map actually performs).
//
// Division-free reduction (the doc's ethos, the CPU reduce ethos): with
// 2^1024 ≡ 2^k + c (mod N), a product is folded down by repeatedly
// replacing its excess above 2^1024 with (hi << k) + c*hi until no
// excess remains; a final conditional subtract finishes. No division,
// no Barrett constants, no per-modulus magic beyond (k, c).
#pragma once

#include <cuda_runtime.h>

#include <cstddef>
#include <cstdint>

namespace vx::gpu {

// Modulus selector: 0 = p (k=64), 1 = q (k=888), 2 = r (k=512).
inline constexpr int FIELD_MOD_P = 0;
inline constexpr int FIELD_MOD_Q = 1;
inline constexpr int FIELD_MOD_R = 2;

// Batch modular multiplication: n elements, each a 1024-bit field element
// as 16 little-endian uint64 limbs. a_elems/b_elems: n x 16 limbs packed.
// Both inputs are taken as ALREADY REDUCED (< N) — that is the field
// invariant every caller shares with the CPU path. out: n x 16 limbs.
// Returns cudaSuccess or the first CUDA error.
cudaError_t field_mulmod_batch(const uint64_t *a_elems, const uint64_t *b_elems,
                               int mod_sel, uint32_t n, uint64_t *out_elems,
                               cudaStream_t stream = 0);

} // namespace vx::gpu
