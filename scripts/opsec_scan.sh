#!/usr/bin/env bash
# OPSEC_SOVEREIGN_SHIELD — tree-wide leak scan (invariant 3).
# Scans the published surface for host paths, personal-network addresses,
# and Cyrillic text. Run before every commit and every release;
# scripts/hooks/pre-commit runs a diff-scoped version of the same gate.
set -uo pipefail

cd "$(dirname "$0")/.."

# Patterns are assembled from fragments so this scanner does not match its
# own regex literals (a scanner that trips on itself is useless).
p_home='/home'
p_users='/Users'
p_192='192\.168\.[0-9]+\.[0-9]+'
p_172='172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+'
PATTERNS="(${p_home}/|${p_users}/|${p_192}|${p_172})"
# Documented, intentional exceptions (never real infrastructure):
#  - src/net/swarm_node.cpp uses 10.0.0.x as a marked SIMULATION range
#    (test fixture "rogue.address = 10.0.0.99", comment "simulation range");
#  - 127.0.0.1 loopback defaults are permitted everywhere.
ALLOWED='10\.0\.0\.[0-9]+|127\.0\.0\.1'
PATHS='src include tests scripts docs .github CMakeLists.txt README.md'

status=0
for p in $PATHS; do
    [ -e "$p" ] || continue
    while IFS= read -r hit; do
        if grep -qE "$ALLOWED" <<<"$hit"; then
            continue
        fi
        echo "OPSEC FAIL: $hit"
        status=1
    done < <(grep -rnE "$PATTERNS" "$p" 2>/dev/null || true)
done

# Cyrillic anywhere on the published surface is banned (standing repo rule).
# Box-drawing separators, em-dashes and the Unicode rune alphabets of the
# WIF visual formats are the established code style and are NOT identity
# signals; Cyrillic would be.
while IFS= read -r hit; do
    echo "OPSEC FAIL (Cyrillic): $hit"
    status=1
done < <(grep -rnP '[\x{0400}-\x{04FF}]' $PATHS 2>/dev/null || true)

if [ "$status" -eq 0 ]; then
    echo "OPSEC SCAN: clean (host paths, private IPs, Cyrillic)"
fi
exit "$status"
