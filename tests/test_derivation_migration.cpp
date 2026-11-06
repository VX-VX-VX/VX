// Derivation migration protocol pins (P1, BACKLOG - genesis migration).
//
// The derivation is FROZEN (version 1). Any future change - e.g. adopting
// the Conditional Involution Guard - must go through the migration
// protocol in docs/DERIVATION_MIGRATION.md:
//   1. bump VortexAttractor::DERIVATION_VERSION (never silently);
//   2. regenerate reference vectors with
//      VX_DUMP_DERIVATION_VECTORS=1 ./test_derivation_migration;
//   3. compare OLD vs NEW across ALL 3072 bits and every derived address;
//   4. nodes refuse identity material from a foreign version (fail-closed).
//
// This suite pins the version-1 vectors (full final state + addresses for
// the canonical seed set, both locked orientations for the canonical seed)
// and proves the comparison machinery detects a single-bit difference.
//
// Dump mode (VX_DUMP_DERIVATION_VECTORS=1) prints the vectors instead of
// asserting - it is the reference-vector utility the migration protocol
// uses; it changes nothing in normal runs.
#include "vx/math/galois_attractor.hpp"
#include "vx/core/types.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using vx::math::VortexAttractor;

namespace {

const std::string kCanonicalSeed =
    "d15c93e51137cb32d0f0ab68524e91451f0d8a7e584a52ccad833d7c9c35396ce8b9cfa766ac99c2214eb228c71099"
    "425cff0dd7f20ba6e3fe81f19b94e7c0bc66a8c37e671273e08ed9060be52c43b19e79614837d911b7418147c04b88"
    "57d5dd83fc362976394a9ceb47f946b2f70e9e94ef62ec0aeca06f280ab1ff023b0814f44d319f30cc1402d7a4e344"
    "61725f06bb83c20035906dd26f4ba2100393c7cbdbba1d1cd57ab5ec0614140f7f58687301a4f22c78f888929daf61"
    "2d9e3469b2fd1f7332a634663fdac32f387c63bc0d6a4fc3e47f62b3baf0c1e0194b78687bf978d1e0b6561501dbaa"
    "6ea17a3ad582b6e3bf4ce818823d8ce38233a2b7cf";

struct DerivationVector {
    std::string label;
    std::string seed;
    bool unlocked;
    std::string x_hex;
    std::string y_hex;
    std::string z_hex;
    std::string nfa;
    std::string ofa;
};

// Version gate: nodes MUST refuse identity material derived under a
// foreign derivation version - never interoperate silently.
bool derivation_versions_compatible(uint32_t a, uint32_t b) noexcept {
    return a == b;
}

// The migration comparator: ALL 3072 bits plus every derived address.
bool vectors_identical(const DerivationVector &a, const DerivationVector &b) {
    return a.x_hex == b.x_hex && a.y_hex == b.y_hex && a.z_hex == b.z_hex && a.nfa == b.nfa &&
           a.ofa == b.ofa;
}

DerivationVector derive(const std::string &label, const std::string &seed, bool unlocked) {
    const auto moduli = vx::core::AttractorModuli::secure_crt();
    const auto r = VortexAttractor::run(seed, 1000, unlocked, moduli);
    DerivationVector v;
    v.label = label;
    v.seed = seed;
    v.unlocked = unlocked;
    v.x_hex = VortexAttractor::bigIntToHex1024(r.finalX);
    v.y_hex = VortexAttractor::bigIntToHex1024(r.finalY);
    v.z_hex = VortexAttractor::bigIntToHex1024(r.finalZ);
    v.nfa = r.addressNFA;
    v.ofa = r.addressOFA;
    return v;
}

void emit(const DerivationVector &v) {
    std::cout << "{\n"
              << "  \"label\": \"" << v.label << "\",\n"
              << "  \"unlocked\": " << (v.unlocked ? "true" : "false") << ",\n"
              << "  \"final_x\": \"" << v.x_hex << "\",\n"
              << "  \"final_y\": \"" << v.y_hex << "\",\n"
              << "  \"final_z\": \"" << v.z_hex << "\",\n"
              << "  \"nfa\": \"" << v.nfa << "\",\n"
              << "  \"ofa\": \"" << v.ofa << "\"\n"
              << "}\n";
}

} // namespace

int main() {
    const bool dump = std::getenv("VX_DUMP_DERIVATION_VECTORS") != nullptr;

    assert(VortexAttractor::DERIVATION_VERSION == 1);
    assert(derivation_versions_compatible(1, 1));
    assert(!derivation_versions_compatible(1, 2));

    // The version-1 canonical vector set. Order and labels are part of the
    // pin: the migration protocol diffs label-by-label.
    std::vector<DerivationVector> current;
    current.push_back(derive("canonical_unlocked", kCanonicalSeed, true));
    current.push_back(derive("canonical_locked", kCanonicalSeed, false));
    {
        std::string s = kCanonicalSeed;
        s.replace(0, 8, "01234567");
        current.push_back(derive("variant_a_unlocked", s, true));
    }
    {
        std::string s = kCanonicalSeed;
        s.replace(0, 8, "89abcdef");
        current.push_back(derive("variant_b_unlocked", s, true));
    }

    if (dump) {
        for (const auto &v : current)
            emit(v);
        return 0;
    }

    // -- Pinned version-1 reference vectors --------------------------------
    // Generated from the frozen derivation (see dump mode above); these are
    // the "old canonical vectors" the migration protocol compares against.
    const std::vector<DerivationVector> pinned = {
        {"canonical_unlocked", kCanonicalSeed, true,
         "0x194feddcbd626fa765bc443063c03b1f35ea08d7878205126c751780bcc0fa4d"
         "28da22ea1d699fc7fbe49b8c8eebd45e56d1c22c51a663646f936846695367a90"
         "5cd3f7cb19e43eff21e92d9b2f3d5d12d1c1526b382e518cb61f5eb1b763176aa"
         "57a436b561b23437855fb293bb49d9e9412b528da3c6e90ab8ed129becc52f",
         "0x3c16b5fd5f95f3f92355a91e44f95fc47bb7b7fe5bd21d74b83e712c6c827a8"
         "c2546fb3ebdf048929b691630f5a75a207babc67319092dbc1d80a84d1c3cc6be"
         "55f1bc9443b94572099ffe167e7a12561b97ded60c57394220568a935a6f3eb37"
         "6adb56823910cf8d6c6b841e4bb526a39d9ac8cc90b81685d66e3c2f3a73690",
         "0xe65ef9673488781ea8a5947c92a26d2a839a8f0cb6887af5837760879a7d029"
         "2514310fb2e5042765f3e89d133bdf21c5cbbc1be440111c4249907943b6da46a"
         "8135280cad9ef0660b63da7f9bd92fc771a4b40a88c21ed526f7503d5008b31a4"
         "2b2af8894c899541a6aa778b7b7525fd49323569dc7ff6d3179bab24e1b6ed9",
         "NFA_V6_O4HmXEAExE6zKrurarTRDZVapms3cqqoJkNRNhmgAA",
         "OFA_V2_O4HmXEAExE6zKrurarTRDZVapms3cqqoJkNRNhmgAA"},
        {"canonical_locked", kCanonicalSeed, false,
         "0xfc6effa90767f1eef1b1abb61b3c4c972cb56e593830a9178bd9db737edf3c99"
         "d8cd5ce1be32ef5df3adf79492b1f913b2ebbe7b7cbcd8557272a3f6a7458b108"
         "df3c064775db75e3d390a1a61e048d8e5d31a1123affe2d10c1cc7fd0be416006"
         "dba503e0678b97128d8954f0c4e75f08871bd73b110dba5e3dcb5229f9e212",
         "0x2cb14d6470d84c36462b4261af5aa755f750e3355b78173cad5e0f0fd5cfd6af"
         "864d60ef915264125d6d24156f3f0f30b7f96aee9174a750661e7afc6be35e107"
         "9bb50e672488d0d6882ed1037d6bd0fc268145739e79679630c0def59a42e8811"
         "a56b1e8a0d0abec14cd079a81b5aaf7e0827243a1a13868d8887feb097684b",
         "0x77fbce936b26c9aeb7895acfe5698b4e3c4294b95764b9b1bd7e65842adae5f"
         "cfb8dbdeb13228557ece70d3801c3ed94790c94c810821c2bdf0c102b2960b899"
         "cb61e341ada4cfa5593c7dfb715b3988f316bfbb9331a96c3e0b41ddc3ff2eec"
         "ce5e968e2d236a2c27b740fd497fb3e359b00f9f24ff4c7fe7975c0a650126c8",
         "NFA_V6_ndi7iIAKDOLZrgAhTNXAHszu6q6_6FEG-6zMzMiMAA",
         "OFA_V2_ndi7iIAKDOLZrgAhTNXAHszu6q6_6FEG-6zMzMiMAA"},
        {"variant_a_unlocked", kCanonicalSeed, true,
         "0x04de83ce3a0e74c946289835624456ec6b62ad309a84565aa34182d2648ca4bd"
         "02e7a494203c4138761b0c7e314768c2295671dd4716b538476a61b87bace5072"
         "224c51306a7e24ff727ad13c3645e8c8678eff22109728d8262ed9f421f9b187f"
         "2f6f4e808ac85ffdf024b88bc22965885be689f8a4e93fa282c5fcf53b5d45",
         "0x61e92d11ff9af0577412dc28c901e936f241c53a589ee4c88c1f30e1c28a854b"
         "3df0a99d491e9197a6d867fe2c9214b9109f06e03014f1a596aa3a2484fd9f268"
         "f119245b3541eb4c8319f31bbd4183c53278995f73383035bb96377e920557d1e"
         "6cc0c782fc65b042e9949e7b0ae91130a4c955e193e52e47fc93dd015f7666",
         "0xd5f559b65b6fda8a8bd644605acd6a017efdc7aadebaffc2807a4f05844dfefe"
         "54cd27aa61b60f24e6e69d130a570cfa962dbbe9e0f011574557945f68ca50c3a"
         "7e152b460980fb84249bb0c90b8059b3053d8be71833e2e0bf2ac71f9db71de89"
         "1444e99c28b2476b9c0b1c1d54d0a9a60c03a33cc5c51f429f08e83961036c",
         "NFA_V6_92-iOaIZIhGRGIiJIhJqp2Z3YjQdwKIIJkOZuW7UAA",
         "OFA_V2_92-iOaIZIhGRGIiJIhJqp2Z3YjQdwKIIJkOZuW7UAA"},
        {"variant_b_unlocked", kCanonicalSeed, true,
         "0xac4502c4527d1113b4b1587c91e67a4be5ea68c30692f723de3808d3185b8d098"
         "ae8091729fb6948df065875abab427d23fcf7ba17aa81b7c24630d275740e7e9c5"
         "863033cfa39a6adf1ade54ad5bc353fbdf386596df9528005aea07821be3adada"
         "dd4dd997abe9565a6ac68535d9e70ae78ffa632141c1d7557b69f5f0edbd",
         "0x72c0fe448bd2a389edb285dd2f52ca23cb33c4c124df94ec117a63ccf5bd9ca9"
         "274153bcd005fb8e462475b67d80276494bd81fee5919c3c36de91affa0a197ca"
         "1d7fd952f9c5291c18d3479262f38022df25a6a8529adc637df1a7917ac49e6c4"
         "ae28bea01b275378c1dafa5b6b3695de6a592a903ad1a5e9711ab5074ef163",
         "0xcead9ef5f9caf7571401170b15d0929af59a2095ad6eec04285f33ae5a10b7f7"
         "9e9620696f5cc367c4facb96bc55944d71b8aef5ff7a919eeef98b0e6971305a6"
         "14d4603dcfa074a012aa796a6cc2c67c474f8fcb6aa72ca64572ea8d6480956b3"
         "097ef73b402cd634cff633fe7c1d66faf5f12735dd440f0e3886a9334f5e62",
         "NFA_V6_YjcIsIRKaqQ3QtEtTNSmSiIh91ydyLMITMSRCOIMAA",
         "OFA_V2_YjcIsIRKaqQ3QtEtTNSmSiIh91ydyLMITMSRCOIMAA"},
    };

    assert(pinned.size() == current.size());
    for (size_t i = 0; i < pinned.size(); ++i) {
        assert(pinned[i].label == current[i].label);
        assert(vectors_identical(pinned[i], current[i]));
    }

    // -- Mutation detection: flipping ONE bit of ANY component must fail ---
    for (size_t i = 0; i < pinned.size(); ++i) {
        for (const int field : {0, 1, 2}) {
            DerivationVector mutated = pinned[i];
            // flip EXACTLY bit 0 of the component's last hex digit
            auto flip_low_bit = [](std::string &hex) {
                const char c = hex.back();
                const int v = (c >= 'a') ? (c - 'a' + 10) : (c - '0');
                const int flipped = (v & 1) ? (v - 1) : (v + 1);
                hex.back() = "0123456789abcdef"[flipped];
            };
            if (field == 0)
                flip_low_bit(mutated.x_hex);
            else if (field == 1)
                flip_low_bit(mutated.y_hex);
            else
                flip_low_bit(mutated.z_hex);
            assert(!vectors_identical(mutated, current[i]));
        }
    }

    std::cout << "DERIVATION MIGRATION: version 1 pinned (" << pinned.size()
              << " vectors, 3072 bits + addresses), "
                 "mutation detection OK\n";
    return 0;
}
