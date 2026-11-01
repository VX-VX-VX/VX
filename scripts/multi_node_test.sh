#!/usr/bin/env bash
# VX multi-node local testnet — automated 3-node check.
#
# Boots three vx_node processes on loopback in a star topology (B and C
# dial A), then verifies:
#   1. all three RPC endpoints come up,
#   2. a transfer mined on A propagates over VX60 and converges on B and C
#      (same tip hash, same balances),
#   3. garbage packets on the VX60 port are counted as corrupted and the
#      node stays alive,
#   4. the in-process split-brain reorg simulation still converges.
#
# Usage:  scripts/multi_node_test.sh [build_dir]
# Ports:  RPC 18088-18090, VX60 19188-19190 (must be free).

set -u

BUILD_DIR="${1:-build}"
NODE="$BUILD_DIR/vx_node"
DATA_ROOT="$(mktemp -d /tmp/vx_multinode.XXXXXX)"

RPC_A=18088; RPC_B=18089; RPC_C=18090
P2P_A=19188; P2P_B=19189; P2P_C=19190

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

expect_eq() { # name got want
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi
}

cleanup() {
    jobs -p | xargs -r kill 2>/dev/null
    wait 2>/dev/null
    rm -rf "$DATA_ROOT"
}
trap cleanup EXIT

[ -x "$NODE" ] || { echo "ERROR: $NODE not found — build the project first"; exit 1; }

echo "[1/5] Minting the demo chain once, then snapshotting it to all nodes"
# The demo block embeds wall-clock time, so each node must start from the
# SAME mined state: run --demo once and copy the data dir (a node joining a
# network always starts from a shared snapshot, never from its own mint).
"$NODE" --demo --data-dir "$DATA_ROOT/a" >/dev/null 2>&1 || {
    echo "ERROR: demo run failed"; exit 1; }
cp -r "$DATA_ROOT/a" "$DATA_ROOT/b"
cp -r "$DATA_ROOT/a" "$DATA_ROOT/c"

echo "[2/5] Starting star topology (B and C dial A on :$P2P_A)"
"$NODE" --serve "$RPC_A" --p2p "$P2P_A" --data-dir "$DATA_ROOT/a" >/dev/null 2>&1 &
sleep 1
"$NODE" --serve "$RPC_B" --p2p "$P2P_B" --peer "127.0.0.1:$P2P_A" --data-dir "$DATA_ROOT/b" >/dev/null 2>&1 &
sleep 1
"$NODE" --serve "$RPC_C" --p2p "$P2P_C" --peer "127.0.0.1:$P2P_A" --data-dir "$DATA_ROOT/c" >/dev/null 2>&1 &

wait_up() { # rpc_port seconds
    for _ in $(seq 1 "$2"); do
        curl -s "localhost:$1/api/status" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}
for p in "$RPC_A" "$RPC_B" "$RPC_C"; do
    expect_eq "RPC :$p is up" "$(wait_up "$p" 5 && echo up)" up
done

echo "[3/5] Transfer on A must propagate over VX60 to B and C"
TX=$(curl -s -X POST "localhost:$RPC_A/api/transfer" -d '{
    "sender":"NFA_V6_CLIqoXuU6o9M9cAcFUGEWe7dsxsM8WqV0RwVQnukAA",
    "receiver":"NFA_V6_iIgiAC7Bohg_wrdof8Vu1y7z0T3zHB3BMxERENEMAA",
    "amount_vx":7}')
TX_TIP=$(printf '%s' "$TX" | python3 -c 'import json,sys; print(json.load(sys.stdin)["block_hash_hex"])')
sleep 1

TIP_A=$(curl -s "localhost:$RPC_A/api/status" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tip_hash_hex"])')
TIP_B=$(curl -s "localhost:$RPC_B/api/status" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tip_hash_hex"])')
TIP_C=$(curl -s "localhost:$RPC_C/api/status" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tip_hash_hex"])')

expect_eq "tip on A matches the transfer block" "$TIP_A" "$TX_TIP"
expect_eq "tip on B matches A" "$TIP_B" "$TIP_A"
expect_eq "tip on C matches A" "$TIP_C" "$TIP_A"
BAL_B=$(curl -s "localhost:$RPC_B/api/accounts" | python3 -c '
import json,sys
for a in json.load(sys.stdin)["accounts"]:
    if a["address"].startswith("NFA_V6_CLIqoXu"): print(a["balance_vx"]); break')
expect_eq "sender balance on B is 74993 VX" "$BAL_B" "74993.00000000"

echo "[4/5] Garbage packets are counted as corrupted; the node stays alive"
CORRUPT_BEFORE=$(curl -s "localhost:$RPC_A/api/swarm/peers" | python3 -c 'import json,sys; print(json.load(sys.stdin)["corrupted_packets_dropped"])')
python3 - "$P2P_A" <<'EOF'
import socket, sys
for _ in range(10):
    s = socket.socket(); s.settimeout(2)
    s.connect(("127.0.0.1", int(sys.argv[1])))
    s.sendall(b"\xde\xad\xbe\xef" + b"\x00" * 60)
    s.close()
EOF
sleep 1
CORRUPT_AFTER=$(curl -s "localhost:$RPC_A/api/swarm/peers" | python3 -c 'import json,sys; print(json.load(sys.stdin)["corrupted_packets_dropped"])')
if [ "$CORRUPT_AFTER" -gt "$CORRUPT_BEFORE" ]; then
    ok "corruption counter rose ($CORRUPT_BEFORE -> $CORRUPT_AFTER)"
else
    bad "corruption counter did not rise"
fi
expect_eq "node A still serving after garbage" "$(wait_up "$RPC_A" 3 && echo up)" up

echo "[5/5] In-process split-brain reorg simulation"
REORG=$(curl -s -X POST "localhost:$RPC_A/api/swarm/simulate_split_reorg")
REORG_OK=$(printf '%s' "$REORG" | python3 -c 'import json,sys; print(json.load(sys.stdin)["reorg_success"])')
expect_eq "split-brain reorg converged" "$REORG_OK" "True"

echo
echo "=== $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
