// Reproducible WOTS+ (w=16, L=67) / XMSS (H=4) benchmark (P2, BACKLOG).
//
// Fixed-iteration, fixed-input measurements of the PQ witness path cost
// centers, split into COLD (per-window first touch: 16 leaf computations
// fill the window cache) and WARM (cache-hit steady state) figures:
//
//   cold window build  - first xmss_root_tree on a fresh window;
//   cold sign          - first pq_sign_message on a fresh window;
//   warm sign          - signs inside an already-built window;
//   warm verify        - detached pq_verify_wots_xmss.
//
// Every printed figure is derived from measured times of THIS binary in
// THIS build type - no constants, no hand-entered multipliers. Ratios
// are computed from the measured means and rounded to one decimal.
//
// Run from a Release build:  ./bench_pq
#include "vx/crypto/pq_signature.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace vx::crypto::pq;

namespace {

std::array<uint8_t, 32> bench_bytes(uint64_t counter) {
    const std::string tag = "VX_PQ_BENCH_V1";
    std::vector<uint8_t> bytes;
    bytes.reserve(tag.size() + 8);
    bytes.insert(bytes.end(), tag.begin(), tag.end());
    for (int i = 0; i < 8; ++i)
        bytes.push_back(static_cast<uint8_t>(counter >> (i * 8)));
    std::array<uint8_t, 32> out{};
    vx::blockchain::VortexSponge256::compute(bytes.data(), bytes.size(), out.data());
    return out;
}

double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

struct Stats {
    double mean = 0.0;
    double mn = 1e300;
    double mx = 0.0;
};

Stats summarize(const std::vector<double> &v) {
    Stats s;
    for (const double x : v) {
        s.mean += x;
        if (x < s.mn)
            s.mn = x;
        if (x > s.mx)
            s.mx = x;
    }
    s.mean /= static_cast<double>(v.size());
    return s;
}

void print_row(const char *label, const Stats &s) {
    std::printf("%-26s %10.3f %10.3f %10.3f   (ms, mean/min/max)\n", label, s.mean, s.mn, s.mx);
}

} // namespace

int main() {
    const auto master = bench_bytes(1);
    const auto pub_seed = pub_seed_from_sk(master);
    const auto msg = bench_bytes(2);

    // Warm the window-1 cache once, then measure the steady state.
    (void)xmss_root_tree(master, pub_seed, 1);

    constexpr int kWarmRuns = 45;
    std::vector<double> sign_ms, verify_ms;
    sign_ms.reserve(kWarmRuns);
    verify_ms.reserve(kWarmRuns);
    std::vector<PqSignatureWitness> witnesses;
    witnesses.reserve(kWarmRuns);
    for (int i = 0; i < kWarmRuns; ++i) {
        const auto t0 = std::chrono::steady_clock::now();
        witnesses.push_back(
            pq_sign_message(static_cast<unsigned>(i % 15), 1, master, pub_seed, msg));
        sign_ms.push_back(ms_since(t0));
    }
    int verified = 0;
    for (int i = 0; i < kWarmRuns; ++i) {
        const auto t0 = std::chrono::steady_clock::now();
        if (pq_verify_wots_xmss(msg, witnesses[static_cast<size_t>(i)]))
            ++verified;
        verify_ms.push_back(ms_since(t0));
    }

    // Cold window builds: windows 2..41 are touched for the first time.
    constexpr int kColdBuilds = 40;
    std::vector<double> cold_build_ms;
    cold_build_ms.reserve(kColdBuilds);
    for (int i = 0; i < kColdBuilds; ++i) {
        const uint32_t w = static_cast<uint32_t>(2 + i);
        const auto t0 = std::chrono::steady_clock::now();
        const auto r = xmss_root_tree(master, pub_seed, w);
        cold_build_ms.push_back(ms_since(t0));
        (void)r;
    }

    // Cold signs: first signature inside windows 100..104.
    constexpr int kColdSigns = 5;
    std::vector<double> cold_sign_ms;
    cold_sign_ms.reserve(kColdSigns);
    for (int i = 0; i < kColdSigns; ++i) {
        const uint32_t w = static_cast<uint32_t>(100 + i);
        const auto t0 = std::chrono::steady_clock::now();
        const auto wit = pq_sign_message(0, w, master, pub_seed, msg);
        cold_sign_ms.push_back(ms_since(t0));
        (void)wit;
    }

    const Stats warm_sign = summarize(sign_ms);
    const Stats warm_verify = summarize(verify_ms);
    const Stats cold_build = summarize(cold_build_ms);
    const Stats cold_sign = summarize(cold_sign_ms);

    std::printf("VX PQ benchmark (WOTS+ w=16 L=67, XMSS H=4, 16 leaves/window)\n");
    std::printf("warm runs: sign=%d verify=%d (verified %d/%d); cold builds=%d; "
                "cold signs=%d\n",
                kWarmRuns, kWarmRuns, verified, kWarmRuns, kColdBuilds, kColdSigns);
    print_row("cold window build", cold_build);
    print_row("cold sign (fresh window)", cold_sign);
    print_row("warm sign", warm_sign);
    print_row("warm verify", warm_verify);
    std::printf("ratios (means): warm verify / warm sign = %.2fx | "
                "cold build / warm sign = %.1fx\n",
                warm_sign.mean / warm_verify.mean, cold_build.mean / warm_sign.mean);
    if (verified != kWarmRuns) {
        std::fprintf(stderr, "bench_pq: verification failure\n");
        return 1;
    }
    return 0;
}
