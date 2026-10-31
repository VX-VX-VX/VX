# Contributing to VX

Thanks for your interest in VX — an experimental post-quantum layer-1
blockchain written in C++26. This document explains how to build, test
and contribute.

## Building from source

### Dependencies

- GCC 14+ (GCC 15/16 recommended; the codebase uses C++26 features)
- CMake 3.24+
- Ninja (or any CMake generator)
- GMP (GNU Multiple Precision)
- GoogleTest (for the test suite; `pacman -S gtest` / `apt install libgtest-dev`)
- OpenSSL (some hashing helpers)

Arch Linux:

```bash
sudo pacman -S git cmake ninja gcc gmp gtest openssl
cmake -S . -B build -G Ninja
cmake --build build -j
```

### Running the tests

```bash
cd build && ctest --output-on-failure
```

All 16 suites must pass. Two locked-arena suites are skipped automatically
when the environment cannot `mlock` the arena (e.g. containerized CI with
a low `RLIMIT_MEMLOCK`) — this is expected and honest behavior, not a
silent weakening of security: the vault constructor itself stays strict.

## Ground rules

- **C++26, clean English comments, no personal data.** Do not commit
  private paths, machine-specific artifacts, binaries or secrets.
  `genesis.bin` and ledger files are derived deterministically at runtime
  and must never be committed.
- **Genesis is derived, not shipped.** The canonical seed is a published
  test vector in `src/blockchain/genesis.cpp`; anything that would embed
  a *real* seed or key into the tree will be rejected.
- **Deterministic output.** Genesis derivation, attractor coordinates and
  frame layouts are bit-exact and covered by tests. If your change moves
  a hash, there must be a documented reason.
- **No silent security trade-offs.** If a test needs to be skipped in a
  constrained environment, gate it on an explicit capability probe —
  never delete or stub the coverage.

## Submitting changes

1. Fork, create a feature branch off `main`.
2. Build clean, `ctest` 16/16 green.
3. Keep commits focused; write commit messages in plain English that
   explain *why*, not just *what*.
4. Open a pull request with a short description of the change and any
   consensus-affecting consequences.

## Reporting bugs

Open a GitHub issue with the build environment (compiler, OS), the
commit hash and a minimal reproduction. For security-sensitive bugs
see [SECURITY.md](SECURITY.md) — do not open public issues for those.

## License

By contributing you agree that your contributions are licensed under
the same license as the repository (see [LICENSE](LICENSE)).
