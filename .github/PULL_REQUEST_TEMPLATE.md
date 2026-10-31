<!-- Thank you for contributing to VX. Keep PRs focused; one logical change per PR. -->

## What and why

<!-- What does this PR change, and what problem does it solve? -->

## Consensus impact checklist

<!-- Tick every box that applies. If none apply, leave all unticked. -->

- [ ] Changes consensus-visible behavior (genesis derivation, hashes, frame layouts, ledger rules)
- [ ] Changes a wire or storage format
- [ ] Adds or changes cryptography (primitives, parameters, key derivation)
- [ ] Touches the vault memory core (arena, page lifecycle, burn paths)

## Evidence

- [ ] Builds clean from a fresh clone
- [ ] `ctest --output-on-failure`: all 16 suites pass (locked-arena suites may SKIP in mlock-less environments — that is expected and documented)
- [ ] New behavior is covered by a new or updated test
- [ ] If consensus-visible behavior changed: the reason is documented in the PR description and in the touched spec section

## Notes for reviewers

<!-- Anything a reviewer should look at first, or known trade-offs. -->
