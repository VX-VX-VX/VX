# VX Roadmap

VX is a research alpha. This roadmap states where the project intends to
go, in what order, and — just as importantly — what is deliberately *not*
promised. No dates are attached: items move when they are done and
verified, not before.

## Shipped — v0.1.8-beta (current)

- 3-Trunk Vortex Attractor (3072-bit, Solinas prime fields, CRT synthesis)
- Deterministic in-core genesis derivation from a published seed vector
- WOTS+ (w=16, L=67) + XMSS (H=4) post-quantum signatures, SegPQ detached
  witnesses (2376 B), PQ-backed-sender enforcement
- Fixed 64 KiB block frames; 112-byte transaction frames; GQC finality
  stamp at a fixed offset
- PoGW proof search + simplified ASERT difficulty (target 5 s, τ = 130)
- Vault memory core (mlock arenas, page lifecycle, burn paths)
- 7-tier key matrix, Shamir 2-of-3 recovery, proof-of-life
- VSDPV mempool pre-filter, VX60 wire protocol, JSON RPC, web console
- 16/16 test suites, CI on Arch (GCC + Clang, C++26)
- Sanitizer CI — ASan + UBSan test pass as a separate job; the pass exposed
  and fixed four real defects (uninitialized vault page pool, literal-length
  NFA field overreads, a 64-bit rotation UB, a use-after-free across a
  ledger reopen in the reorg path)
- libFuzzer targets for block-frame parsing, WOTS+/XMSS witness
  verification and VX60 wire ingest, wired into CI (`fuzz/`, deterministic
  seeds)
- CodeQL static analysis on the C++ core and the web console
- RPC cookbook (`docs/RPC_COOKBOOK.md`) — task-oriented recipes for the
  JSON RPC with live-captured responses: transfers, PQ signing, guard
  replays, VM traces
- Multi-node runbook (`docs/MULTI_NODE_RUNBOOK.md`) — live VX60 testnet:
  3-node block propagation with tip convergence, garbage-packet
  resistance, in-process split-brain reorg; plus the P2P wiring that made
  it real (`--p2p`/`--peer` now bind, handshake, relay and gossip)
- RPC input fuzzing (`fuzz/fuzz_rpc.cpp`) — the whole 34-endpoint JSON
  surface behind a public `route()` catch-all; oversized numerals on the
  transfer/audit paths no longer throw out of the RPC, and CI runs the
  target for 200k fixed-seed execs
- VX60-SEC encrypted transport (BIP-324-analog) — ML-KEM-768 (FIPS 203,
  ACVP-KAT-verified) WARM/COLD handshake, sealed channels, MAC-only mode
  for public block bodies, per-IP connection caps, fail-closed SEC-channel
  guard on the raw block path, identity strikes and a durable banlist
- Multi-node full-cycle test — 3 nodes SEC↔SEC on localhost: dial, sealed
  handshake, block seal + propagation, GQC finalization, version strike,
  durable banlist, restart refusal
- Dandelion++ epoch stem channels for privacy sidecars
- GQC genesis epoch committee — the first-epoch quorum set is a
  master-signed whitelist in the deterministic genesis config; share
  collection is gated on committee membership
- SVA-8192 Sovereign Vault crypto core — the cold-custody address class
  (Merkle-counter over 256 one-time leaves on the tree's own sponge);
  ledger wiring is the next item
- Chaos fuzzer for the VX60 wire path; 53/53 test suites with assert,
  AddressSanitizer and ThreadSanitizer lanes

## Next — 0.2.x queue

- SVA-8192 vault ledger wiring (spend path, counter atomicity, undo)
- SLH-DSA (FIPS 205) signature backend with ACVP test vectors
- Bitmasked m-of-n XMSS GQC committee (n ≤ 64, accountable BFT)
- PQ-threshold finality (checkpoint gadget over verified XMSS quorum)
- QRNG beacon for the epoch seed
- Timelocks (TLMK/MSRK/EK streaming) and the C1-C5 contract phases

## Mid term — earning the right to be called a protocol

3. **Independent cryptographic review** — priority order: VortexSponge256,
   the WOTS+/XMSS wiring and key-lifecycle state machine, then the
   attractor's collision behavior. See whitepaper §15 — this is the single
   most important item on the list.
4. **Signature backend as an interface** — pluggable hash-based schemes
   behind the same witness API. SLH-DSA (FIPS 205, SPHINCS+) is the first
   candidate, next in the 0.2.x queue; the custom sponge dependency can
   then be reduced or removed without touching the frame format.
5. **Formal collision analysis of the address derivation** — including the
   documented 18-bit prefix drop in the NFA payload.
6. **GQC validator-set formation** — the epoch-1 committee ships as a
   master-signed whitelist in the deterministic genesis config; the
   economics and admission logic for later epochs (VRF-weighted selection,
   age/reputation gates) remain research-grade (whitepaper §15, open
   item 4).

## Long term — conditional on everything above

7. **Public testnet** — real PoGW economics, external validators, live
    ASERT under adversarial load.
8. **Mainnet criteria** — published, explicit, and gated on the audit
    outcome: no mainnet before (4) and (5) conclude, whatever the calendar
    says.

## Explicitly not promised

- Privacy of amounts (the ledger is transparent; phantom decoys are
  structural obfuscation, not cryptographic privacy).
- Smart-contract expressiveness beyond the 24-opcode VX VM.
- Side-channel hardening of the big-integer path (GMP's guarantees, not
  VX's).
- A token sale, presale, or any form of fundraising. VX is AGPLv3
  research software.

---

Feedback on priorities is welcome — open an issue or start a Discussion.
Security topics go through private reporting (see SECURITY.md).
