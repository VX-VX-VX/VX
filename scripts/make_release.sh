#!/usr/bin/env bash
# OPSEC_SOVEREIGN_SHIELD — deterministic release archives (invariant 2).
# Release zips are generated straight from the Git tree via git archive:
# entry mtimes come from the commit timestamp, uid/gid are 0, no host
# filesystem metadata, no absolute paths. A .sha256 sidecar is written
# next to the archive (integrity, NOT authenticity - verification of
# authenticity is the GPG tag signature).
#
# Usage:
#   scripts/make_release.sh <out_dir> [ref]          zip with vx-main-<sha>/ prefix
#   scripts/make_release.sh <out_dir> [ref] --flat   zip at archive root (legacy layout)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
ref="${2:-HEAD}"
short="$(git rev-parse --short "$ref")"
out="$1"; mkdir -p "$out"
zipname="vx-main-${short}.zip"

if [ "${4:-}" = "--flat" ] || [ "${3:-}" = "--flat" ]; then
    git archive --format=zip "$ref" -o "${out}/${zipname}"
else
    git archive --format=zip --prefix="vx-main-${short}/" "$ref" -o "${out}/${zipname}"
fi

(cd "$out" && sha256sum "$zipname" > "${zipname}.sha256")
echo "archive:  ${out}/${zipname}"
echo "checksum: $(cat "${out}/${zipname}.sha256")"
echo "verify:   (cd ${out} && sha256sum -c ${zipname}.sha256)"
echo "bind:     commit ${short}  |  tag signature: git verify-tag <tag>"
echo "NOTE: the checksum proves download integrity only; the GPG tag"
echo "      signature is the authenticity mechanism."
