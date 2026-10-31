#include "vx/core/rdtsc_profiler.hpp"
#include "vx/core/memory_vault.hpp"
#include "vx/math/fast_reduction.hpp"
#include "vx/math/tensor_v6.hpp"
#include "vx/state/galois_trie.hpp"
#include "vx/vm/vortex_vm.hpp"
#include "vx/crypto/simd_accel.hpp"
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <numeric>
#include <gmpxx.h>
#include "vx/core/hw_intrinsics.hpp"

namespace vx::core {

namespace {

// Optimizer sink: every contour folds its result here so no measurement can
// be dead-code-eliminated.
volatile uint64_t g_profiler_sink = 0;

inline void sink(uint64_t v) noexcept { g_profiler_sink ^= v; }

} // namespace

RdtscSample RdtscProfiler::profile(const char* name, uint64_t iters,
                                   const std::function<void()>& op) {
    RdtscSample s;
    s.op_name = name;
    s.iterations = iters;

    op(); // warm-up: first-touch pages, branch predictors, caches

    std::vector<uint64_t> cycles;
    cycles.reserve(iters);
    const auto w0 = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < iters; ++i) {
        const uint64_t t0 = hw::cycle_counter();
        op();
        cycles.push_back(hw::cycle_counter() - t0 + hw::cycle_floor());
    }
    const auto w1 = std::chrono::steady_clock::now();

    std::sort(cycles.begin(), cycles.end());
    s.min_cycles = cycles.front();
    s.max_cycles = cycles.back();
    s.p50_cycles = cycles[iters / 2];
    s.p99_cycles = cycles[std::min<uint64_t>(iters - 1, (iters * 99) / 100)];
    s.cycles_per_iter =
        static_cast<double>(std::accumulate(cycles.begin(), cycles.end(), uint64_t{0})) /
        static_cast<double>(iters);
    s.estimated_ns =
        std::chrono::duration<double, std::nano>(w1 - w0).count() / static_cast<double>(iters);
    return s;
}

std::vector<RdtscSample> RdtscProfiler::run_full_profile() const {
    std::vector<RdtscSample> out;
    out.reserve(6);

    // ── 1. solinas_fast_reduction_1024b ─────────────────────────────────────
    {
        mpz_class high = (mpz_class(1) << 1024) - 1;
        mpz_class low = (mpz_class(1) << 1023) + 12345;
        mpz_class reduced = 0;
        out.push_back(profile("solinas_fast_reduction_1024b", iters_.solinas, [&] {
            reduced = math::FastReducer::fast_reduce_p(high, low, false);
            sink(static_cast<uint64_t>(mpz_class(reduced % 7919).get_ui()));
        }));
    }

    // ── 2. avx2_sponge_4way_hash ────────────────────────────────────────────
    {
        uint8_t in[4][128];
        uint8_t digests[4][32];
        for (int b = 0; b < 4; ++b)
            for (int i = 0; i < 128; ++i) in[b][i] = static_cast<uint8_t>(i * 7 + b);
        uint64_t rot = 0;
        out.push_back(profile("avx2_sponge_4way_hash", iters_.sponge, [&] {
            in[0][0] = static_cast<uint8_t>(rot++);
            crypto::sponge256_4way_avx2(in[0], in[1], in[2], in[3],
                                        digests[0], digests[1], digests[2], digests[3]);
            sink(digests[0][0]);
        }));
    }

    // ── 3. tensor_v6_arx_step ───────────────────────────────────────────────
    {
        math::TensorV6 tensor;
        std::array<uint64_t, 16> seed{};
        for (size_t i = 0; i < seed.size(); ++i) seed[i] = 0x9E3779B97F4A7C15ULL * (i + 1);
        auto matrix = tensor.act_i_init(seed);
        std::array<uint64_t, 16> phi{};
        for (size_t i = 0; i < phi.size(); ++i) phi[i] = 0xBF58476D1CE4E5B9ULL * (i + 3);
        out.push_back(profile("tensor_v6_arx_step", iters_.tensor, [&] {
            tensor.act_ii_mma(matrix, phi); // one step of the 16384-bit state
        }));
    }

    // ── 4. vortex_vm_opcode_dispatch ────────────────────────────────────────
    {
        // Four NOP dispatches + HALT: dividing by 5 yields per-instruction cost.
        const auto bytecode = vm::VortexVM::assemble("NOP\nNOP\nNOP\nNOP\nHALT\n");
        std::array<uint8_t, vm::VortexVM::BYTECODE_MAX_SIZE> code{};
        std::memcpy(code.data(), bytecode.data(), bytecode.size());
        constexpr double kDispatches = 5.0;

        vm::VortexVM machine;
        vm::VortexVM::ExecutionContext ctx;
        auto s = profile("vortex_vm_opcode_dispatch", iters_.vm, [&] {
            const auto res = machine.execute(code.data(), ctx);
            sink(res.total_landauer_gas);
        });
        s.min_cycles = static_cast<uint64_t>(s.min_cycles / kDispatches);
        s.p50_cycles = static_cast<uint64_t>(s.p50_cycles / kDispatches);
        s.p99_cycles = static_cast<uint64_t>(s.p99_cycles / kDispatches);
        s.max_cycles = static_cast<uint64_t>(s.max_cycles / kDispatches);
        s.cycles_per_iter /= kDispatches;
        s.estimated_ns /= kDispatches;
        out.push_back(std::move(s));
    }

    // ── 5. vault_ephemeral_sign_and_burn ──────────────────────────────────
    {
        // 8 MiB arena; each sign+burn cycle consumes one pool page slot.
        MemoryCore vault(8 * 1024 * 1024);
        vault.initialize(0xC17ADE1ULL);
        out.push_back(profile("vault_ephemeral_sign_and_burn", iters_.vault, [&] {
            blockchain::Transaction tx{};
            std::memcpy(tx.sender_nfa, "PROFILER_VAULT_SENDER_000000000000000000", 42);
            std::memcpy(tx.receiver_nfa, "PROFILER_VAULT_RECV_0000000000000000000", 42);
            blockchain::sign_transaction(tx);
            const auto rep = vault.sign_ephemeral_in_vault(tx);
            sink(rep.key_lifetime_rdtsc_cycles);
        }));
    }

    // ── 6. sgmt_merkle_proof_verify ─────────────────────────────────────────
    {
        state::GaloisTrie trie;
        std::array<uint8_t, 32> key{}, val{};
        for (size_t i = 0; i < 16; ++i) {
            key[i] = static_cast<uint8_t>(0xA0 + i);
            val[i] = static_cast<uint8_t>(0x5E ^ i);
        }
        trie.put(key.data(), val.data());
        const auto proof = trie.generate_proof(key.data());
        const auto root = trie.root_hash();
        out.push_back(profile("sgmt_merkle_proof_verify", iters_.sgmt, [&] {
            const bool ok = state::GaloisTrie::verify_proof(root.data(), key.data(),
                                                            val.data(), proof);
            sink(ok ? 1u : 0u);
        }));
    }

    return out;
}

} // namespace vx::core
