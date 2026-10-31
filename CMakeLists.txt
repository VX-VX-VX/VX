cmake_minimum_required(VERSION 3.25)
project(VortexCore VERSION 6.0.0 LANGUAGES CXX)

# Enforce C++26 standard
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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

# Industrial deep cryptographic verification suite
add_executable(crypto_deep_tests tests/crypto_deep_tests.cpp)
target_link_libraries(crypto_deep_tests PRIVATE vx_core gtest gtest_main)

# 64 KB block architecture test suite
add_executable(test_block tests/test_block.cpp)
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

enable_testing()
add_test(NAME VortexMathTest COMMAND test_vortex)
add_test(NAME VortexDeepCryptoTest COMMAND crypto_deep_tests)
add_test(NAME VortexBlockTest COMMAND test_block)
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
    foreach(fuzz_target IN ITEMS fuzz_block_frame fuzz_pq_witness fuzz_wire)
        add_executable(${fuzz_target} fuzz/${fuzz_target}.cpp)
        target_compile_options(${fuzz_target} PRIVATE -fsanitize=fuzzer)
        target_link_libraries(${fuzz_target} PRIVATE vx_core -fsanitize=fuzzer)
    endforeach()
endif()
