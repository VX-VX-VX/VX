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
- 16/16 test suites, CI on Arch (GCC, C++26)

## Near term — hardening the artifact

These items make the codebase itself more trustworthy before anything is
asked of the network:

1. **Sanitizer CI** — an ASan + UBSan test pass as a separate CI job.
2. **Fuzzing** — libFuzzer targets for frame parsing, witness verification
   and RPC input; "fuzzed since day one" as a standing property, not a
   one-off.
3. **Compiler matrix** — Clang alongside GCC in CI; kill any accidental
   GCC-only assumptions.
4. **Static analysis** — CodeQL (or clang-tidy baseline) with a clean-or-
   documented policy.
5. **RPC cookbook** — task-oriented docs: send a transaction, verify a
   witness, replay a chain, read an audit report.
6. **Multi-node local testnet runbook** — scripted two/three-node setup
   exercising VX60 sync and split-brain reorg convergence outside unit
   tests.

## Mid term — earning the right to be called a protocol

7. **Independent cryptographic review** — priority order: VortexSponge256,
   the WOTS+/XMSS wiring and key-lifecycle state machine, then the
   attractor's collision behavior. See whitepaper §15 — this is the single
   most important item on the list.
8. **Signature backend as an interface** — pluggable hash-based schemes
   (e.g. SPHINCS+ or LMS/HSS) behind the same witness API, so the custom
   sponge dependency can be reduced or removed without touching the frame
   format.
9. **Formal collision analysis of the address derivation** — including the
   documented 18-bit prefix drop in the NFA payload.
10. **GQC validator-set formation** — economics and admission logic for
    the quorum set; today the threshold gadget exists, the set-formation
    story is research-grade (whitepaper §15, open item 4).

## Long term — conditional on everything above

11. **Public testnet** — real PoGW economics, external validators, live
    ASERT under adversarial load.
12. **Mainnet criteria** — published, explicit, and gated on the audit
    outcome: no mainnet before (7) and (8) conclude, whatever the calendar
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
