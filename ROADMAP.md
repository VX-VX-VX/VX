# VX Roadmap

VX is a research alpha. This roadmap states where the project intends to
go, in what order, and — just as importantly — what is deliberately *not*
promised. No dates are attached: items move when they are done and
verified, not before.

Every code change passes the standing process: adversarial review
(`vx-audit`) as a gate before commit, a periodic full-tree zero-day hunt
(`vx-zeroday`) as a background CVE-hunt loop, the three-lane suite
(assert / ASan / TSan) before every tag, and UTC/GPG-signed commits.

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
- 16/16 test suites, CI on Arch (GCC + C++26)
- Sanitizer CI — ASan + UBSan test pass as a separate job; the pass exposed
  and fixed four real defects (uninitialized vault page pool, literal-length
  NFA field overreads, a 64-bit rotation UB, a use-after-free across a
  ledger reopen in the reorg path)
- libFuzzer targets for block-frame parsing, WOTS+/XMSS witness
  verification, VX60 wire ingest and RPC input (fuzz/), wired into CI
- CodeQL static analysis on the C++ core and the web console
- RPC cookbook and multi-node runbook (docs/)
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
  (Merkle-counter over 256 one-time leaves on the tree's Authorization =
  revealed preimage; 256 one-time leaves → tombstone after the 256th spend;
  the wallet physically cannot spend a 257th time)
- 53/53 test suites across assert, ASan and TSan lanes

## Next — 0.2.x queue

The 0.2.x line is a fixed sequence of phases. The order is deliberate:
standard primitives first (B), then the committee machinery that depends on
them (C), then the world-first composite (D), then the research-heavy tail
(E–G). Phases are not reordered, and none of them is skipped.

- **0.2.0 — Phase A: SVA-8192 vault ledger wiring** (in progress; the
  8/8 wiring suite is green and pending the audit gate + commit). The
  cold-custody address class becomes spendable: spend path through the
  ledger, counter atomicity under concurrent blocks, undo/reorg rollback of
  the one-time-leaf counter, tombstone after the 256th spend in every code
  path, witness sidecar durability, and the vault entry lifecycle
  (active → spent → tombstone) enforced ledger-side.
- **0.2.1 — Phase B: SLH-DSA (FIPS 205) signature backend** with ACVP
  test vectors. The witness API becomes pluggable behind the same frame
  format, reducing the custom-sponge dependency for the signature layer.
  Bit-exact against ACVP (internalProjection.json) vectors — a KAT failure
  is a shipped bug, never a tolerance issue.
- **0.2.2 — Phase C: Bitmasked m-of-n XMSS GQC committee** (n ≤ 64,
  accountable BFT). The genesis whitelist committee graduates from a
  fixed quorum to accountable m-of-n: bitmasked share attribution, per-member
  accountability, no DKG (deliberately rejected — DKG breaks liveness and
  costs tens of thousands of lines; the bitmask construction avoids it).
- **0.2.3 — Phase D: PQ-threshold finality** — the checkpoint gadget over
  a verified XMSS quorum. Threshold signatures on stateful post-quantum
  trees: on ECDSA this is settled science (MuSig/FROST); on stateful XMSS
  it has no prior art we are aware of, enabled by the one-shot leaf ledger
  and rollover certificates. This is the flagship item of the 0.2.x line.
- **0.2.4 — Phase E: QRNG beacon for the epoch seed** — the epoch seed
  stops being master-signed and starts being QRNG-fed (external beacon
  verification, fail-closed on beacon absence).
- **0.2.5 — Phase F: Timelocks** (TLMK/MSRK/EK streaming) — vault entries
  with time-bound spend windows, and the EK streaming track.
- **0.2.6–0.2.10 — Phase G: C1–C5 contract phases** — one version per
  phase, each behind the K1–K10 spec gate (see the contracts spec C0):
  calldata/ABI, final gas table, FAULT policy, producer/verifier gas
  discrepancy class, and the contract lifecycle. C0 ratification by the
  owner is a hard precondition for every Phase G item.

## Mid term — 0.3.x

The 0.3.x line turns the protocol into a platform. None of it starts
before the 0.2.x line is tagged and its audit trail is complete.

- **Contracts C0 ratification** — the K1–K10 spec (contracts spec C0)
  needs owner ratification; every Phase G item is gated on it. C0
  ratification is scheduled to start the 0.3.x window.
- **VX60-SEC M2–M5** — the remaining VX60-SEC milestones (1-RTT KEM, PFS
  hardening, channel resumption, release-hunt of the transport itself).
- **DKSAP-Galois stealth nicknames** — the owner-specced stealth address
  class (SK/IVK/Kspend/Kview, SGMT registration, Pstealth, radar on IVK,
  1-of-16 detection). Beta-scheduled after 0.1.8, lands in the 0.3.x window.
- **view_tag 7x radar** — detection acceleration for the stealth track.
- **SGMT-tx wiring** — the SGMT cell registry becomes the transaction
  surface for vault and stealth entries.
- **zk-cocoon / SNARK track** — an owner decision gates this: beta ships
  before SNARK; the SNARK track is a separate major after 0.2.x. No
  commitment before that decision.
- **Explorer, wallet GUI, tooling** — the ecosystem layer that carries
  most of the path to 400k+ lines: block explorer, wallet GUI (web demo
  exists), VX VM tooling (assembler/disassembler), testnet infrastructure
  (P4 validator list, P5 domain + VPS fleet).
- **Citadel round 2** — mlock/DONTDUMP hardening round for the vault core.

## Long term — 0.4.x and beyond

- **Public testnet** — real PoGW economics, external validators, live
  ASERT under adversarial load; P4/P5 infrastructure items resolve here.
- **400k+ line horizon** — full-VM (C1–C5 complete, SGMT cells, calldata,
  gas table, FAULT rollback, byte-exact verifier reproduction), the
  ecosystem layer, and the testnet infrastructure. This is a months-long
  roadmap, not a single branch.
- **Mainnet criteria** — published, explicit, and gated on the audits:
  no mainnet before the independent cryptographic review (4) and the
  formal collision analysis (5) conclude, whatever the calendar says.
- **External audit gate** — the vx-zeroday loop is internal discipline;
  it does not replace the independent external audit required by the
  mainnet gate.

## Explicitly not promised

- Privacy of amounts (the ledger is transparent; phantom decoys are
  structural obfuscation, not cryptographic privacy).
- Smart-contract expressiveness beyond the 24-opcode VX VM.
- Side-channel hardening of the big-integer path (GMP's guarantees, not
  VX's).
- A token sale, presale, or any form of fundraising. VX is AGPLv3
  research software.

## Open owner items

- **P4** — validator list (testnet admission).
- **P5** — domain + 4 VPS fleet (seed hosts; until then a node without
  `--seed` starts alone — PEX/ADDRS discovery works, but needs at least
  one seed to find the network).
- **Melt vector** — the 300 s → 60 s melt decision (beta config, last
  open consensus parameter).
- **CLAUDE.md untracked** — the repo CLAUDE.md is untracked; decide
  track/ignore.

---

Feedback on priorities is welcome — open an issue or start a Discussion.
Security topics go through private reporting (see SECURITY.md).
