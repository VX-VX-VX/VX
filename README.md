# VX — Vortex Sovereign OS (VX L1)

![language](https://img.shields.io/badge/C%2B%2B-26-blue)
![build](https://img.shields.io/badge/build-CMake%20%2B%20Ninja-green)
![license](https://img.shields.io/badge/license-AGPLv3%20%2B%20clause-lightgrey)
![tests](https://img.shields.io/badge/ctest-16%2F16-brightgreen)

**VX** is an experimental Layer-1 blockchain with a fixed 64 KiB block frame, a
deterministic 3072-bit chaotic attractor at its consensus core, and a
post-quantum signature layer built exclusively from hash-based cryptography.

## Why post-quantum by construction

VX contains **no elliptic-curve cryptography and no RSA anywhere in the
consensus or wallet stack**. There is no secp256k1, no Ed25519, no ECDLP — and
therefore no attack surface for Shor's algorithm. Every signature on the chain
is a **WOTS+ (w=16, L=67) one-time signature inside an XMSS (H=4) Merkle tree**,
hash-keyed by VortexSponge256:

| Property | Value |
|---|---|
| Signature scheme | WOTS+ w=16, L=67 + XMSS H=4 (hash-based, stateful) |
| Hash layer | VortexSponge256 (custom ARX sponge) |
| Shor-vulnerable operations | **0** |
| Grover security margin | 128-bit |
| Classical security margin | 256-bit |
| Detached witness size | 2 376 B |
| Transaction frame | 112 B (invariant) |
| Block frame | 65 536 B (invariant) |

A MITM that recomputes the keyless checksum still has to forge the full
Winternitz checksum chain and the XMSS Merkle path — the defense is layered,
not single-point.

## Core architecture

- **3-Trunk Vortex Attractor** — a 3072-bit chaotic dynamical system evaluated
  over secure CRT moduli (P = 2^1024−2^64−1747, Q = 2^1024−2^888−3943,
  R = 2^1024−2^512−267799). Block headers carry the attractor's real final
  state (X, Y, Z coordinates) as consensus metadata.
- **Fixed-frame storage** — every block is exactly 65 536 bytes, mmap-parsed
  zero-copy in O(1). No serialization layer, no variable-length surprises.
- **PoGW (Proof-of-Genuine-Work)** mining with ASERT difficulty adjustment and
  GQC finality.
- **Vortex VM** with a Landauer thermodynamic gas model — every opcode pays a
  metered cost derived from the Landauer limit, not from gas tables.
- **Swarm P2P (VX60 wire protocol)** — CRC32C-checked frames, split-brain
  reorg convergence, Dandelion++ propagation and an MEV shield.
- **Vault memory** — a mlock'ed page arena where signing keys are expanded,
  used once, and burned (`PageState::BURNED`) with volatile zeroization and
  cache-line eviction.
- **17-format WIF matrix** — one 2048-bit canonical seed is renderable as 17
  sovereign wallet-import formats, including the full-Unicode rune pair
  (F1/F2): the entire 2048-bit key as 102 runes over a 1 119 33-symbol
  alphabet (20.0846 bits/rune), roundtrip-exact.

## The two build editions

```bash
# Public Core (default) — portable, hardening degrades gracefully
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# Nakamoto Vault — mandatory mlock arena, cache-line burns (_mm_clflush),
# DMI product_uuid hardware binding
cmake -S . -B build_vault -DCMAKE_BUILD_TYPE=Release -DVX_BUILD_VAULT=ON
```

The Nakamoto Vault edition is for dedicated signing hardware. The Public Core
edition builds and passes the identical test suite everywhere; mlock failures
are warnings, and hardware binding uses synthetic fallback vectors.

## Quickstart

```bash
# 1. Build (C++26 compiler required — GCC 14+ recommended, GCC 16 tested)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# 2. Run the full test suite (tests reconstruct genesis deterministically)
ctest

# 3. Start a node with RPC on port 8088 — the node derives Block #0
#    deterministically from the published seed on first run:
./build/vx_node --serve 8088 --port 8088 --data-dir ./data
```

The node serves a JSON RPC at `http://localhost:8088`:

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/status` | GET | Chain height, tip hash, supply, engine state |
| `/api/crypto/lab` | POST | Attractor run + full 17-format WIF matrix |
| `/api/crypto/pq_sign` | POST | WOTS+/XMSS sign with Vault burn lifecycle |
| `/api/crypto/pq_verify` | POST | Detached witness verification + attack demos |
| `/api/security/audit` | POST | Red-team attack simulations (`attack_type`) |
| `/api/crypto/canonical` | GET | Canonical test-vector profiles |

The web console (`web/`) is a React + TypeScript PWA that speaks the same RPC.

## Canonical test vectors

The canonical genesis attractor seed documented in the source
(`d15c93e5…`, 512 hex chars) is the **public release test vector** used for
Block #0 and deterministic KATs (randomly generated, published for bit-for-bit
reproducibility). Every node reconstructs Block #0 in-process from this seed —
genesis is never shipped as a file and never copied. **Never use the seed for
live keys.**

## Test suite

16 ctest targets, including: canonical differential verification against the
TS reference implementation, 100 randomized 3072-bit CRT homomorphism checks,
Strict Avalanche Criterion across the key matrix, NIST SP 800-22 monobit
frequency testing on folded digests, WIF matrix fuzzing, WOTS+/XMSS known
answer tests, split-brain reorg convergence over real TCP loopback, and the
Vault burn-lifecycle tests. All 16 pass in **both** build editions.

## Experimental disclaimer

**VX is experimental, unaudited software.** It is a research artifact exploring
chaotic-system consensus, thermodynamic gas metering and hash-based
post-quantum signing. Do not use it to secure real value. The cryptographic
primitives are custom constructions that have not undergone independent
third-party audit. Use it to read, to verify, to reproduce — and to break.

## License

AGPLv3 with an additional anti-state / anti-military-surveillance clause — see
[LICENSE](LICENSE).
