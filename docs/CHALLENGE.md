# The Vortex Challenge

A newcomer's path through VX, in the tradition of Bitcoin's oldest rituals:
*"don't trust — verify"*, taken one step further. In Bitcoin you verify the
genesis block someone gave you. In VX there is no genesis block to be given —
**you derive it yourself**, from a published seed, and the whitepaper is the
complete specification of how.

Four levels. Each one is optional; together they take a curious newcomer
from "it compiles" to "I understand the whole consensus core". No cheating
police exist — the honor system is the point: level 2 is only meaningful if
you don't peek at the C++ source first.

---

## Level 1 — Run the chain and catch it in the act

Build from source ([README](../README.md#building-from-source)) and start a
node on a fresh data directory:

```bash
cmake -S . -B build -G Ninja && cmake --build build -j
./build/vx_node --data-dir /tmp/vx_first
```

On first run the node derives block #0 from the published seed and prints:

```
✓ Genesis #1 address: NFA_V6_O4HmXEAExE6zKrurarTRDZVapms3cqqoJkNRNhmgAA
✓ Genesis #1 balance: 254000000000000 atomics (2.54M VX)
```

**Check:** start the RPC (`--serve 18088 --data-dir /tmp/vx_first`) and GET
`/api/status`. The `tip_hash_hex` must be

```
ff327c330756241cd7c66a2f207c19202a2d7d38bbe9ffebb23510a72fd75be1
```

If that hash appears — you just *proved* that your machine, your compiler
and your build independently recomputed the exact same block #0 that every
other VX node in the world derives. There is no file to trust: if the code
were wrong, the hash would differ.

**You've completed Level 1 when:** you can explain, without the README, why
the hash matching means nobody can sneak a different genesis past you.

## Level 2 — Write the attractor from the whitepaper alone

The rules: whitepaper §3–§5 only. Do **not** read `src/math/`,
`src/blockchain/genesis.cpp`, or the RPC crypto endpoints until you're done.
Any language with big integers works — Python + `gmpy2` is enough.

Your target: given the canonical seed from whitepaper §7.1, a program of
yours — written from the formulas alone — must print

```
NFA_V6_O4HmXEAExE6zKrurarTRDZVapms3cqqoJkNRNhmgAA
```

That is the address of block #0 itself, so there is no ambiguity and no
partial credit: either your Act I–IV pipeline, the xor-fold and the
base64url encoding are all bit-exact, or the string is different.

Pitfalls worth discovering yourself (each one is a real place where
implementations drift):

- the rotation in Act I uses `Y₀ mod 64`, in Act III it uses `y mod 64`
  **plus 1000** — read §4.3 carefully;
- "1024-bit rotation" means *cyclic* rotation of the whole integer, not a
  shift;
- the cubic map reduces in three *different* fields — which value goes in
  which field is stated in §4.2;
- cross-injection is a *cyclic shift* of the cubes, not an identity;
- the address drops the first 3 base64url characters — §5 explains exactly
  which bits that costs you.

Expected effort: an evening. The reward: after this, every other subsystem
of VX (witnesses, PoGW, the frame layout) is *readable*, because you have
already rebuilt the hardest arithmetic in it.

**You've completed Level 2 when:** your program prints the address above
having never imported a single line from this repository.

## Level 3 — Break a butterfly on a wheel (SAC probe)

Flip exactly one bit of the canonical seed. Run 20 rounds of your Level 2
implementation twice (original and flipped seed), and compute the Hamming
distance across all 3072 state bits after each round, as in whitepaper §6.

Cross-check against the shipped implementation:

```bash
curl -s http://localhost:18088/api/crypto/canonical | python3 -m json.tool
```

**Observe:** how few rounds it takes to reach ~50% divergence, and that it
never collapses back. This is the property the sponge's original bug broke
(§3.5 tells that story), and the reason avalanche is *tested*, not assumed.

**You've completed Level 3 when:** you can state — with your own numbers —
how fast one seed bit becomes 3072 bits of difference.

## Level 4 — The vanity ladder (open-ended)

Bitcoin's puzzle addresses hid escalating prizes in ever-harder keys. VX has
no prizes to hide, but the attractor makes an honest research ladder
possible anyway: **find a 512-hex-character seed whose 1000-round address
payload starts with a given prefix.**

The ladder, easiest to hardest:

| Rung | Required payload prefix | Expected effort |
|---|---|---|
| 1 | any single digit `0`–`9` | minutes |
| 2 | `VX` | minutes-to-hours |
| 3 | `VX0` | hours (CPU) |
| 4 | `VXVX` | a good multicore afternoon |
| 5 | `VXVXVX` | don't — unless you have a GPU cluster and a reason |

Payload means the 42 base64url characters after `NFA_V6_`. Nothing about
the ladder is consensus-relevant — vanity addresses are a pure
proof-of-work on your own hardware and a fun way to internalize how the
seed→address pipeline behaves under bulk search.

Post your shortest winning seeds (and the address) in a Discussion. The
level 4 record table lives there, updated by whoever beats it last.

---

## Why this exists

The strongest thing a protocol can give a newcomer in their first hour is a
task where *the protocol proves itself to them* rather than asking to be
believed. Bitcoin did it with the block schedule and the genesis message.
VX can do it with determinism: the whole chain state is a pure function of
published constants, so the deepest verification in the system is also the
easiest one to attempt.

If any level teaches you something the whitepaper says wrong or the code
does differently — that is the single most valuable bug report this project
can receive. Please file it.
