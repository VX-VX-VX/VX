#!/usr/bin/env bash
# VX — one-command build wrapper (Linux only).
#
# Wraps the CMake configure + build + optional test run into a single
# script so a user never has to remember the flags. The two editions
# (Public Core / Nakamoto Vault) never share a build directory.
#
# Usage:
#   scripts/build.sh                 # Public Core, Release, all targets
#   scripts/build.sh tests           # ... + run the full ctest suite
#   scripts/build.sh vault           # Nakamoto Vault edition (Release)
#   scripts/build.sh vault tests     # Vault edition + tests
#   scripts/build.sh --deps          # install build dependencies (sudo)
#   scripts/build.sh --debug         # Debug build instead of Release
#   scripts/build.sh -j N            # parallelism (default: nproc)
#
# Requirements: C++26 compiler (GCC 14+), CMake >= 3.25, GMP/GMP++.
# Ninja is used when present, GNU make otherwise.
set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

mode="release"    # release | vault
run_tests=0
want_deps=0
build_type="Release"
jobs="$(nproc 2>/dev/null || echo 4)"

while [ $# -gt 0 ]; do
    case "$1" in
        tests)        run_tests=1 ;;
        vault)        mode="vault" ;;
        --deps)       want_deps=1 ;;
        --debug)      build_type="Debug" ;;
        -j)           shift; jobs="${1:?usage: -j N}" ;;
        *)            echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

# ---- dependency installation (the only sudo step, and only on request) ----
if [ "$want_deps" -eq 1 ]; then
    if command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --needed git cmake ninja gcc gmp gtest
    elif command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y git cmake ninja-build g++ libgmp-dev libgtest-dev
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y git cmake ninja-build gcc-c++ gmp-devel gtest-devel
    else
        echo "unsupported distro: install git cmake ninja gcc gmp gtest manually" >&2
        exit 1
    fi
fi

# ---- toolchain checks (fail with a readable message, not a cmake wall) ----
for tool in cmake; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing tool: $tool — run scripts/build.sh --deps" >&2
        exit 1
    fi
done
if ! command -v ninja >/dev/null 2>&1; then
    echo "note: ninja not found, falling back to GNU make (slower)" >&2
    gen="Unix Makefiles"
else
    gen="Ninja"
fi

if [ "$mode" = "vault" ]; then
    bdir="build_vault"
    extra=(-DVX_BUILD_VAULT=ON)
    echo "edition: Nakamoto Vault (mandatory mlock, DMI hardware binding)"
else
    bdir="build"
    extra=()
    echo "edition: Public Core"
fi

# ---- configure ----
# A stale build dir configured with a different generator (e.g. Unix
# Makefiles left over from a make-based attempt) aborts configure — wipe
# it automatically, the user never has to know about CMakeCache.txt.
if [ -f "$bdir/CMakeCache.txt" ]; then
    if ! grep -q "^CMAKE_GENERATOR:INTERNAL=$gen\$" "$bdir/CMakeCache.txt"; then
        echo "stale build dir uses a different generator — recreating $bdir"
        rm -rf "$bdir"
    fi
fi
echo "configure: cmake -S . -B $bdir -DCMAKE_BUILD_TYPE=$build_type -G '$gen' ${extra[*]}"
cmake -S . -B "$bdir" -DCMAKE_BUILD_TYPE="$build_type" -G "$gen" "${extra[@]}"

# ---- build ----
echo "build: $jobs jobs"
cmake --build "$bdir" -j "$jobs"

# ---- tests ----
if [ "$run_tests" -eq 1 ]; then
    echo "test: ctest --output-on-failure"
    (cd "$bdir" && ctest --output-on-failure)
fi

echo "done — binary: $bdir/vx_node"
