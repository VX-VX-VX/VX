#!/usr/bin/env bash
# Soft-mode test lane (owner directive 2026-11-14): the laptop has 12C/24T
# but only 14 GiB RAM — three PARALLEL instrumented builds swap the desktop
# to death. One lane at a time, 8 build jobs, low scheduling priority,
# ctest -j4. Usage: scripts/test_lane_soft.sh <build_dir>
set -euo pipefail
dir="$1"
cd "$dir"
cmake --build . -j8 >/dev/null 2>&1
ctest -j4 2>&1 | tail -3
