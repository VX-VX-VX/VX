cmake_minimum_required(VERSION 3.25)
project(VortexCore VERSION 6.0.0 LANGUAGES CXX)

# Enforce C++26 standard
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Forensic hygiene (OPSEC_SOVEREIGN_SHIELD, invariant 2) ───────────────────
# Host-absolute paths must never reach __FILE__, assert() text, symbol or
# debug tables of any published binary: every build maps the local source and
# build directories to relative paths at the compiler level.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=."
        "-fdebug-prefix-map=${CMAKE_SOURCE_DIR}=."
        "-fmacro-prefix-map=${CMAKE_SOURCE_DIR}=."
        "-fdebug-prefix-map=${CMAKE_BINARY_DIR}=."
    )
endif()

# ── Build edition ────────────────────────────────────────────────────────────
# VX_BUILD_VAULT=OFF (default) → Public Core: portable, hardening features
#   degrade gracefully; hardware binding uses synthetic fallback vectors.
# VX_BUILD_VAULT=ON → Nakamoto Vault: mandatory mlock arena, cache-line
#   burns (_mm_clflush), real /sys/class/dmi/id/product_uuid hardware binding.
option(VX_BUILD_VAULT "Build the Nakamoto Vault edition (mandatory mlock, cache-line burn, real DMI hardware binding)" OFF)
if(VX_BUILD_VAULT)
    add_compile_definitions(VX_SOVEREIGN_ARCHITECT=1)
    message(STATUS "Edition: NAKAMOTO VAULT (mandatory mlock + cache-line burn + DMI hardware binding)")
else()
    message(STATUS "Edition: PUBLIC CORE (portable hardening, synthetic hardware vectors)")
endif()

# -- Demo keys (BACKLOG 0.10) -------------------------------------------------
# VX_DEMO_KEYS=OFF (default) -> production: the /api/crypto/pq_sign
#   demo_key:"spender" signer is compiled out. The genesis PQ binding of the
#   demo spender to the published demo key is NOT gated: it is consensus
#   data and must validate identically in every build.
#   The pinned GENESIS_2 mint receiver address stays ungated - it is a
#   consensus address, never a key.
# VX_DEMO_KEYS=ON -> demo/test builds: the RPC demo signer is wired back in
#   so the demo economy and the multi-node harness run end to end.
option(VX_DEMO_KEYS "Compile the RPC demo_key signer path (genesis demo spender binding is consensus data, always on)" OFF)
if(VX_DEMO_KEYS)
    add_compile_definitions(VX_DEMO_KEYS=1)
    message(STATUS "Demo keys: ENABLED (RPC demo_key signer; genesis binding is always consensus data)")
else()
    message(STATUS "Demo keys: compiled out (production build)")
endif()

# Find OpenMP
find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    set(HAVE_OPENMP 1)
    message(STATUS "OpenMP found: ${OpenMP_CXX_FLAGS}")
else()
    set(HAVE_OPENMP 0)
    message(STATUS "OpenMP not found, building without parallel support")
endif()

# Optimization & warning flags
if(MSVC)
    add_compile_options(/W4 /WX /Ot /Oi /Gy /EHsc /std:c++latest)
    if(HAVE_OPENMP)
        add_compile_options(/openmp)
    endif()
else()
    add_compile_options(
        -O3
        -march=native
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -pthread
    )
    if(HAVE_OPENMP)
        add_compile_options(${OpenMP_CXX_FLAGS})
    endif()
endif()

# Find GMP / GMPXX
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(GMPXX gmpxx)
endif()

# Core static library
add_library(vx_core STATIC
    src/math/galois_attractor.cpp
    src/math/fast_reduction.cpp
    src/math/tensor_v6.cpp
    src/math/vsdpv_filter.cpp
    src/wif/wif_matrix.cpp
    src/blockchain/block.cpp
    src/blockchain/genesis.cpp
    src/storage/block_store.cpp
    src/rpc/http_server.cpp
    src/crypto/simd_accel.cpp
    src/crypto/zk_key_matrix.cpp
    src/crypto/canonical_vectors.cpp
    src/crypto/key_import.cpp
    src/neural/virtual_tensor.cpp
    src/state/mempool.cpp
    src/consensus/pogw_miner.cpp
    src/vm/vortex_vm.cpp
    src/net/swarm_node.cpp
    src/state/undo_engine.cpp
    src/state/galois_trie.cpp
    src/consensus/gqc_finality.cpp
    src/core/rdtsc_profiler.cpp
    src/security/chaos_fuzzer.cpp
    src/core/memory_vault.cpp
    src/core/rt_scheduler.cpp
    src/crypto/pq_signature.cpp
)

target_include_directories(vx_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/state>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/net>
)

if(GMPXX_FOUND)
    target_link_libraries(vx_core PUBLIC ${GMPXX_LIBRARIES})
    target_include_directories(vx_core PUBLIC ${GMPXX_INCLUDE_DIRS})
else()
    target_link_libraries(vx_core PUBLIC gmpxx gmp)
endif()

if(HAVE_OPENMP)
    target_link_libraries(vx_core PUBLIC OpenMP::OpenMP_CXX)
endif()

# Main node executable
add_executable(vx_node src/main.cpp)
target_link_libraries(vx_node PRIVATE vx_core)
if(HAVE_OPENMP)
    target_link_libraries(vx_node PRIVATE OpenMP::OpenMP_CXX)
endif()

# Mathematical verification test executable
add_executable(test_vortex tests/test_vortex.cpp)
target_link_libraries(test_vortex PRIVATE vx_core)

# Fold-window contract test (companion to docs/ADDRESS_SECURITY.md)
add_executable(test_fold_window tests/test_fold_window.cpp)
target_link_libraries(test_fold_window PRIVATE vx_core)

# VortexSponge512 (v2 sponge) contract tests - BACKLOG 0.15
add_executable(test_sponge512 tests/test_sponge512.cpp)
target_link_libraries(test_sponge512 PRIVATE vx_core gtest gtest_main)

# VortexSponge1024 (v3 sponge) contract tests - owner directive 2026-11-06,
# the certified home for the address-v2 fold (BACKLOG 2.17 remedy)
add_executable(test_sponge1024 tests/test_sponge1024.cpp)
target_link_libraries(test_sponge1024 PRIVATE vx_core gtest gtest_main)

# VX2 address format contract tests - owner directive 2026-11-06
# (docs/ADDRESS_FORMATS_V2.md: own format, better than Bitcoin's)
add_executable(test_address_v2 tests/test_address_v2.cpp)
target_link_libraries(test_address_v2 PRIVATE vx_core gtest gtest_main)

# Attractor degeneracy hunt - BACKLOG 2.8
add_executable(test_attractor_degeneracy tests/test_attractor_degeneracy.cpp)
target_link_libraries(test_attractor_degeneracy PRIVATE vx_core)

# CRT seam collision theorems - P0 formal analysis pins
# (docs/CRT_COLLISION_ANALYSIS.md, owner audit 2026-11-05/06)
add_executable(test_crt_seam_theorems tests/test_crt_seam_theorems.cpp)
target_link_libraries(test_crt_seam_theorems PRIVATE vx_core)
add_executable(test_derivation_migration tests/test_derivation_migration.cpp)
target_link_libraries(test_derivation_migration PRIVATE vx_core)
add_executable(test_digest_uniformity tests/test_digest_uniformity.cpp)
target_link_libraries(test_digest_uniformity PRIVATE vx_core)

# Industrial deep cryptographic verification suite
add_executable(crypto_deep_tests tests/crypto_deep_tests.cpp)
target_link_libraries(crypto_deep_tests PRIVATE vx_core gtest gtest_main)

# 64 KB block architecture test suite
add_executable(test_block tests/test_block.cpp)
target_link_libraries(test_block PRIVATE vx_core gtest gtest_main)

add_executable(test_documented_gaps tests/test_documented_gaps.cpp)
target_link_libraries(test_documented_gaps PRIVATE vx_core gtest gtest_main)
target_link_libraries(test_block PRIVATE vx_core gtest gtest_main)

# Mempool test suite
add_executable(test_mempool tests/test_mempool.cpp)
target_link_libraries(test_mempool PRIVATE vx_core gtest gtest_main)

# VM test suite
add_executable(test_vm tests/test_vm.cpp)
target_link_libraries(test_vm PRIVATE vx_core gtest gtest_main)

# Chain reorg test suite
add_executable(test_reorg tests/test_reorg.cpp)
target_link_libraries(test_reorg PRIVATE vx_core gtest gtest_main)

# Crash/persistence torture: 100 simulated torn-state trials (store, undo
# journal, GQC sidecar, displaced journal) + 30 real SIGKILL trials.
add_executable(test_crash_torture tests/test_crash_torture.cpp)
target_link_libraries(test_crash_torture PRIVATE vx_core gtest gtest_main)

# WAL intent marker: crash-consistent append for BlockStore (recovery
# matrix: torn frame healed, fsynced frame kept, fail-closed paths pinned).
add_executable(test_wal_marker tests/test_wal_marker.cpp)
target_link_libraries(test_wal_marker PRIVATE vx_core gtest gtest_main)

# Boundary-value torture on the money math: exact-balance drains, dust
# boundary, UINT64_MAX amounts, UINT32_MAX fees, coinbase claims (0, floor,
# 1001 VX), GENESIS_2 mint edges, 580-tx block, PQ 16-leaf cap.
add_executable(test_boundary_torture tests/test_boundary_torture.cpp)
target_link_libraries(test_boundary_torture PRIVATE vx_core gtest gtest_main)

# Reorg carousel stress test: two node views, 13 partition/fork/heal cycles,
# displaced-frame integrity, undo-journal survival, GQC finality interplay.
add_executable(test_reorg_carousel tests/test_reorg_carousel.cpp)
target_link_libraries(test_reorg_carousel PRIVATE vx_core gtest gtest_main)

# Bifurcation oracle: the same deterministic chain built twice (parent process
# + fork()ed child); per-block canonical state digests must match exactly —
# catches hidden consensus nondeterminism (hash-map order, float math,
# pointer-dependent sorting).
add_executable(test_bifurcation tests/test_bifurcation.cpp)
target_link_libraries(test_bifurcation PRIVATE vx_core gtest gtest_main)

# 1000-block deterministic stress chain: build, invariant sweeps every 100
# blocks, PRNG rollback probes with fresh-prefix replay equality, displaced
# frames, GQC checkpoints, mempool churn.
add_executable(test_chain_stress tests/test_chain_stress.cpp)
target_link_libraries(test_chain_stress PRIVATE vx_core gtest gtest_main)

# Vault Memory test suite
add_executable(test_vault_memory tests/test_vault_memory.cpp)
target_link_libraries(test_vault_memory PRIVATE vx_core gtest gtest_main)

# ZK Key Matrix test suite
add_executable(test_zk_matrix tests/test_zk_matrix.cpp)
target_link_libraries(test_zk_matrix PRIVATE vx_core gtest gtest_main)

# Tensor V6 test suite
add_executable(test_tensor_v6 tests/test_tensor_v6.cpp)
target_link_libraries(test_tensor_v6 PRIVATE vx_core gtest gtest_main)

# Swarm P2P / VX60 wire protocol test suite (Phase 31/32)
add_executable(test_swarm_p2p tests/test_swarm_p2p.cpp)
target_link_libraries(test_swarm_p2p PRIVATE vx_core gtest gtest_main)

# Galois Trie (SGMT) test suite (Phase 35, test #11)
add_executable(test_galois_trie tests/test_galois_trie.cpp)
target_link_libraries(test_galois_trie PRIVATE vx_core gtest gtest_main)

# Landauer VM + Dandelion++ + MEV shield test suite (Phase 34/33/36, test #12)
add_executable(test_landauer_vm_mev tests/test_landauer_vm_mev.cpp)
target_link_libraries(test_landauer_vm_mev PRIVATE vx_core gtest gtest_main)

add_executable(test_gqc_ring_stealth tests/test_gqc_ring_stealth.cpp)
target_link_libraries(test_gqc_ring_stealth PRIVATE vx_core gtest gtest_main)

add_executable(test_vault_htlc tests/test_vault_htlc.cpp)
target_link_libraries(test_vault_htlc PRIVATE vx_core gtest gtest_main)

add_executable(test_chaos_fuzzer tests/test_chaos_fuzzer.cpp)
target_link_libraries(test_chaos_fuzzer PRIVATE vx_core gtest gtest_main)

# Post-Quantum hash-based signature engine (WOTS+/XMSS) test suite (Phase 46, test #16)
add_executable(test_pq_signatures tests/test_pq_signatures.cpp)
target_link_libraries(test_pq_signatures PRIVATE vx_core gtest gtest_main)
add_executable(test_pq_rollover tests/test_pq_rollover.cpp)
target_link_libraries(test_pq_rollover PRIVATE vx_core)
add_executable(test_pq_rollover_wiring tests/test_pq_rollover_wiring.cpp)
target_link_libraries(test_pq_rollover_wiring PRIVATE vx_core)

# PQ benchmark (BACKLOG P2): reproducible root/sign/verify measurements.
# A manual target, NOT a ctest entry - benchmarks do not gate CI.
add_executable(bench_pq tests/bench_pq.cpp)
target_link_libraries(bench_pq PRIVATE vx_core)

# ASERT PoGW difficulty retarget test suite (BACKLOG 0.9 remainder)
add_executable(test_retarget tests/test_retarget.cpp)
target_link_libraries(test_retarget PRIVATE vx_core gtest gtest_main)

# -- BACKLOG 0.10 (Stage C) test suites ---------------------------------------
# RPC auth token gate (mutating endpoints fail closed without the token).
add_executable(test_rpc_auth tests/test_rpc_auth.cpp)
target_link_libraries(test_rpc_auth PRIVATE vx_core gtest gtest_main)

# Key import validation (strict canonical decode, checksum, address match).
add_executable(test_key_import tests/test_key_import.cpp)
target_link_libraries(test_key_import PRIVATE vx_core gtest gtest_main)

# Stage D hardening suites: half-applied-block commit guard (apply integrity)
# and mempool admission wiring (RPC -> mempool -> miner seal -> ledger).
add_executable(test_apply_integrity tests/test_apply_integrity.cpp)
target_link_libraries(test_apply_integrity PRIVATE vx_core gtest gtest_main)

add_executable(test_mempool_admission tests/test_mempool_admission.cpp)
target_link_libraries(test_mempool_admission PRIVATE vx_core gtest gtest_main)

# Test executables must keep assertions live in every configuration.
# Release defines NDEBUG, which silently compiles every assert() in the
# custom-main suites out of existence — a green lane then proves only
# "did not crash" (found 2026-11-04; zero-trust review discipline).
foreach(tgt test_vortex crypto_deep_tests test_block test_documented_gaps
            test_mempool test_vm test_reorg test_reorg_carousel test_bifurcation
            test_vault_memory test_zk_matrix test_tensor_v6 test_swarm_p2p
            test_galois_trie test_landauer_vm_mev test_gqc_ring_stealth
            test_vault_htlc test_chaos_fuzzer test_pq_signatures test_retarget
            test_chain_stress test_boundary_torture test_crash_torture
            test_wal_marker
            test_rpc_auth test_key_import
            test_apply_integrity test_mempool_admission test_fold_window
            test_sponge512 test_sponge1024 test_address_v2
            test_attractor_degeneracy test_pq_rollover
            test_pq_rollover_wiring
            test_crt_seam_theorems test_derivation_migration
            test_digest_uniformity)
    target_compile_options(${tgt} PRIVATE -UNDEBUG)
endforeach()

enable_testing()
add_test(NAME VortexMathTest COMMAND test_vortex)
add_test(NAME VortexFoldWindowTest COMMAND test_fold_window)
add_test(NAME VortexSponge512Test COMMAND test_sponge512)
add_test(NAME VortexSponge1024Test COMMAND test_sponge1024)
add_test(NAME VortexAddressV2Test COMMAND test_address_v2)
add_test(NAME VortexAttractorDegeneracyTest COMMAND test_attractor_degeneracy)
add_test(NAME VortexCrtSeamTheoremsTest COMMAND test_crt_seam_theorems)
add_test(NAME VortexDerivationMigrationTest COMMAND test_derivation_migration)
add_test(NAME VortexDigestUniformityTest COMMAND test_digest_uniformity)
add_test(NAME VortexDeepCryptoTest COMMAND crypto_deep_tests)
add_test(NAME VortexBlockTest COMMAND test_block)
add_test(NAME VortexDocumentedGapsTest COMMAND test_documented_gaps)
add_test(NAME VortexMempoolTest COMMAND test_mempool)
add_test(NAME VortexVMTest COMMAND test_vm)
add_test(NAME VortexChainReorgTest COMMAND test_reorg)
add_test(NAME VortexVaultMemoryTest COMMAND test_vault_memory)
add_test(NAME VortexZkKeyMatrixTest COMMAND test_zk_matrix)
add_test(NAME VortexTensorV6Test COMMAND test_tensor_v6)
add_test(NAME VortexSwarmP2PTest COMMAND test_swarm_p2p)
add_test(NAME VortexGaloisTrieTest COMMAND test_galois_trie)
add_test(NAME VortexLandauerMevTest COMMAND test_landauer_vm_mev)
add_test(NAME VortexGqcRingStealthTest COMMAND test_gqc_ring_stealth)
add_test(NAME VortexVaultHtlcTest COMMAND test_vault_htlc)
add_test(NAME VortexChaosFuzzerTest COMMAND test_chaos_fuzzer)
add_test(NAME VortexPqSignatureTest COMMAND test_pq_signatures)
add_test(NAME VortexPqRolloverTest COMMAND test_pq_rollover)
add_test(NAME VortexPqRolloverWiringTest COMMAND test_pq_rollover_wiring)
add_test(NAME VortexRetargetTest COMMAND test_retarget)
add_test(NAME VortexReorgCarouselTest COMMAND test_reorg_carousel)
add_test(NAME VxBifurcationOracleTest COMMAND test_bifurcation)
add_test(NAME VortexChainStressTest COMMAND test_chain_stress)
add_test(NAME VortexBoundaryTortureTest COMMAND test_boundary_torture)
add_test(NAME VxCrashTortureTest COMMAND test_crash_torture)
add_test(NAME VortexWalMarkerTest COMMAND test_wal_marker)
add_test(NAME VortexRpcAuthTest COMMAND test_rpc_auth)
add_test(NAME VortexKeyImportTest COMMAND test_key_import)
add_test(NAME VortexApplyIntegrityTest COMMAND test_apply_integrity)
add_test(NAME VortexMempoolAdmissionTest COMMAND test_mempool_admission)

# ── libFuzzer targets (Tier-2 hardening) ─────────────────────────────────────
# Standalone fuzz harnesses for the three highest-risk parse/verify surfaces:
# block frames, WOTS+/XMSS witness verification and VX60 wire ingest.
# libFuzzer requires Clang; with any other compiler the option is ignored so
# a plain `cmake -B build` stays untouched.
option(VX_BUILD_FUZZERS "Build libFuzzer harnesses (Clang only)" OFF)
if(VX_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "VX_BUILD_FUZZERS=ON requires Clang (libFuzzer)")
    endif()
    foreach(fuzz_target IN ITEMS fuzz_block_frame fuzz_pq_witness fuzz_wire fuzz_rpc fuzz_undo_journal fuzz_reorg)
        add_executable(${fuzz_target} fuzz/${fuzz_target}.cpp)
        target_compile_options(${fuzz_target} PRIVATE -fsanitize=fuzzer)
        target_link_libraries(${fuzz_target} PRIVATE vx_core -fsanitize=fuzzer)
    endforeach()
endif()
