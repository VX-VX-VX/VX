# Security Policy

VX is an **experimental research alpha**. It has not been independently
audited and must not be trusted with real funds. That said, security
reports are taken seriously.

## Internal review discipline

Development runs on a zero-trust process (see the BACKLOG working
rules): every change to cryptography, consensus, the wire protocol,
storage, money math or authorization passes an adversarial security
review before it is committed, findings are fixed or pinned honestly,
and every reproduced defect becomes an automated regression test. This
is our own discipline, not an audit — it does not substitute for
independent verification, which remains not performed.

## Supported versions

| Version | Supported |
|---|---|
| `main` (v0.1.8-beta) | ✅ |
| anything older | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's **private vulnerability reporting** (repository → Security
tab → "Report a vulnerability"). Reports there reach the maintainers
privately and confidentially.

Please include:

- the commit hash you tested against;
- a minimal reproduction (test case, command line or RPC transcript);
- your build environment (compiler, OS, flags);
- your assessment of impact, if you have one.

If you found the issue by fuzzing or automated analysis, say so — it
helps triage.

## Scope

In scope:

- post-quantum signature layer: WOTS+ (w=16) one-time keys, XMSS (H=4)
  trees, detached 2376-byte witnesses — forgeries, malleability,
  nonce-reuse;
- VX60-SEC transport: ML-KEM-768 handshake, sealed channels, the MAC-only
  mode for public block bodies — handshake downgrades, channel-state
  confusion, tag/banlist bypasses, per-IP cap circumvention;
- 3-Trunk Vortex Attractor and GQC consensus stamping — coordinate
  manipulation, deterministic-derivation breakage;
- GQC epoch committee — share-pool injection by non-members, whitelist
  signature malleability, quorum-threshold manipulation;
- vault memory core — key material leaking outside locked arenas,
  burn/lifecycle bypasses;
- SVA-8192 vault derivation — leaf-reuse, Merkle-path forgery,
  counter-desync;
- ledger state machine — double-spend, balance bypass, reward
  over-mint, genesis forgery;
- RPC HTTP server and VX60 wire protocol — memory safety, request
  smuggling, unauthenticated state mutation, RPC auth-token bypass.

Out of scope:

- the scripted demo mode (`--demo`) — it intentionally mints demo
  balances;
- test vectors and deterministic public seeds — they are published on
  purpose;
- "I ran the alpha and lost play coins" — the software is not for real
  funds yet.

## What to expect

- acknowledgment within 7 days;
- a fix or a documented mitigation plan once the report is confirmed;
- public disclosure coordinated with the reporter after a fix lands.

There is no paid bounty program at this stage — credit in the release
notes is the currency of the day.
