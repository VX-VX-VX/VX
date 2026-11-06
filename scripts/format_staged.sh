#!/usr/bin/env bash
# OPSEC_SOVEREIGN_SHIELD — format the staged line ranges of every staged
# C++ file in place (companion to scripts/hooks/pre-commit, invariant 5).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
changed=0
while IFS= read -r f; do
    case "$f" in *.cpp|*.cc|*.hpp|*.h) ;; *) continue ;; esac
    # New-file hunk header "@@ -a,b +start,count @@": emit start:end lines.
    ranges=$(git diff --cached -U0 -- "$f" |
             awk '/^@@/{split($3,a,","); s=substr(a[1],2)+0;
                  n=(a[2]==""?1:a[2]+0); if(n>0) print s":"(s+n-1)}')
    [ -n "$ranges" ] || continue
    args=()
    for r in $ranges; do args+=(--lines="$r"); done
    clang-format -i "${args[@]}" "$f"
    git add "$f"
    echo "formatted: $f (lines $(echo "$ranges" | tr '\n' ' '))"
    changed=1
done < <(git diff --cached --name-only)
[ "$changed" -eq 1 ] || echo "nothing to format in the staged C++ files"
