#!/usr/bin/env bash
# OPSEC_SOVEREIGN_SHIELD — UTC commit wrapper (invariant 1).
# All commits are born timezone-sterile: UTC clock, explicit +0000 epoch
# dates for author AND committer, regardless of the host's local settings.
# Every commit is GPG-signed: -S is explicit (a host without commit.gpgsign
# still signs), and a missing signing key aborts the commit fail-closed.
# Usage: scripts/commit_utc.sh [git commit options...]
set -euo pipefail

if ! git config --get user.signingkey >/dev/null 2>&1; then
    echo "commit_utc.sh: no user.signingkey configured — refusing to commit unsigned" >&2
    exit 1
fi

now="$(date -u +%s)"
export TZ=UTC
export GIT_AUTHOR_DATE="${now} +0000"
export GIT_COMMITTER_DATE="${now} +0000"
exec git commit -S "$@"
