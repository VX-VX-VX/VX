# Security Policy

VX is an **experimental research alpha**. It has not been independently
audited and must not be trusted with real funds. That said, security
reports are taken seriously.

## Supported versions

| Version | Supported |
|---|---|
| `main` (v0.0.1-alpha) | ✅ |
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
- 3-Trunk Vortex Attractor and GQC consensus stamping — coordinate
  manipulation, deterministic-derivation breakage;
- vault memory core — key material leaking outside locked arenas,
  burn/lifecycle bypasses;
- ledger state machine — double-spend, balance bypass, reward
  over-mint, genesis forgery;
- RPC HTTP server and VX60 wire protocol — memory safety, request
  smuggling, unauthenticated state mutation.

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
