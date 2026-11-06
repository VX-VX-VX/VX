#!/usr/bin/env bash
# OPSEC_SOVEREIGN_SHIELD — format the staged line ranges of every staged
# C++ file in place (companion to scripts/hooks/pre-commit, invariant 5).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
changed=0
while IFS= read -r f; do
    case "$f" in *.cpp|*.cc|*.hpp|*.h) ;; *) continue ;; esac
    ranges=$(git diff --cached -U0 -- "$f" | awk '/^@@/{gsub("[^0-9,+]","",$3); print $3}' | tr -d '+')
    [ -n "$ranges" ] || continue
    args=()
    for r in $ranges; do
        start=${r%%,*}; end=${start}; [ "$r" = "$start" ] || end=${r##*,}
        args+=(--lines="$start:$end")
    done
    clang-format -i "${args[@]}" "$f"
    git add "$f"
    echo "formatted: $f (lines $(echo "$ranges" | tr '\n' ' '))"
    changed=1
done < <(git diff --cached --name-only)
[ "$changed" -eq 1 ] || echo "nothing to format in the staged C++ files"
