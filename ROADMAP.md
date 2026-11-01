# VX Roadmap

VX is a research alpha. This roadmap states where the project intends to
go, in what order, and — just as importantly — what is deliberately *not*
promised. No dates are attached: items move when they are done and
verified, not before.

## Shipped — v0.0.1-alpha (current)

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

## Near term — hardening the artifact

These items make the codebase itself more trustworthy before anything is
asked of the network:

2. **RPC input fuzzing** — the JSON surface is still only covered by the
   chaos fuzzer's fixed vectors; a libFuzzer target needs the RPC parser
   extracted into a callable unit first.

## Mid term — earning the right to be called a protocol

3. **Independent cryptographic review** — priority order: VortexSponge256,
   the WOTS+/XMSS wiring and key-lifecycle state machine, then the
   attractor's collision behavior. See whitepaper §15 — this is the single
   most important item on the list.
4. **Signature backend as an interface** — pluggable hash-based schemes
   (e.g. SPHINCS+ or LMS/HSS) behind the same witness API, so the custom
   sponge dependency can be reduced or removed without touching the frame
   format.
5. **Formal collision analysis of the address derivation** — including the
   documented 18-bit prefix drop in the NFA payload.
6. **GQC validator-set formation** — economics and admission logic for
    the quorum set; today the threshold gadget exists, the set-formation
    story is research-grade (whitepaper §15, open item 4).

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
