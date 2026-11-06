#!/usr/bin/env bash
# OPSEC_SOVEREIGN_SHIELD — UTC commit wrapper (invariant 1).
# All commits are born timezone-sterile: UTC clock, explicit +0000 epoch
# dates for author AND committer, regardless of the host's local settings.
# Usage: scripts/commit_utc.sh [git commit options...]
set -euo pipefail
now="$(date -u +%s)"
export TZ=UTC
export GIT_AUTHOR_DATE="${now} +0000"
export GIT_COMMITTER_DATE="${now} +0000"
exec git commit "$@"
