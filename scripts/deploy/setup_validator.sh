#!/usr/bin/env bash
# VX — per-machine validator setup (plan step 4 runbook, P5 phase).
# ONE script per machine: dependencies, node build, RPC token, systemd unit,
# monit config, firewall. Idempotent: re-running refreshes unit/config,
# never overwrites an existing data dir or token.
#
# Usage:
#   sudo ./setup_validator.sh --index N --p2p-port 19088 --rpc-port 8088 \
#        [--peers "IP:PORT[,IP:PORT]"] [--release /path/to/vx-main-<sha>.zip]
#   sudo ./setup_validator.sh --index N --source /path/to/repo
#
# NEVER USE ON A MACHINE THAT HOLDS LIVE KEYS. Validator keys are provisioned
# in the P4 phase from the owner's offline master key; infrastructure only.
#
# Security posture (fail-closed by default):
#   - RPC binds all interfaces but mutating endpoints REQUIRE a token
#     (VX_RPC_TOKEN_FILE); without it they answer 401. The firewall does
#     NOT open the RPC port to the world: the owner reaches it over an SSH
#     tunnel. The P2P port is the only public service.
#   - Node runs as a dedicated non-login user (vxuser), data dir 0750,
#     token file root-owned 600.
#   - systemd hardening: NoNewPrivileges, ProtectSystem=strict, ProtectHome,
#     PrivateTmp, empty CapabilityBoundingSet, RestrictAddressFamilies.
set -euo pipefail

INDEX=0
P2P_PORT=19088
RPC_PORT=8088
PEERS=""
RELEASE_ZIP=""
SOURCE_DIR=""
VX_HOME=/var/lib/vx
VX_USER=vxuser
VX_GROUP=vxuser
ETC=/etc/vx
BIN=/opt/vx

log() { echo "[setup] $*"; }
die() { echo "[setup] FATAL: $*" >&2; exit 1; }

# ---------------------------------------------------------------- args
while [ $# -gt 0 ]; do
    case "$1" in
        --index)      INDEX="$2"; shift 2 ;;
        --index=*)    INDEX="${1#*=}"; shift ;;
        --p2p-port)   P2P_PORT="$2"; shift 2 ;;
        --p2p-port=*) P2P_PORT="${1#*=}"; shift ;;
        --rpc-port)   RPC_PORT="$2"; shift 2 ;;
        --rpc-port=*) RPC_PORT="${1#*=}"; shift ;;
        --peers)      PEERS="$2"; shift 2 ;;
        --peers=*)    PEERS="${1#*=}"; shift ;;
        --release)    RELEASE_ZIP="$2"; shift 2 ;;
        --release=*)  RELEASE_ZIP="${1#*=}"; shift ;;
        --source)     SOURCE_DIR="$2"; shift 2 ;;
        --source=*)   SOURCE_DIR="${1#*=}"; shift ;;
        *) die "unknown arg: $1" ;;
    esac
done
[ "$INDEX" -ge 0 ] && [ "$INDEX" -le 255 ] || die "index out of range"
[ "$SOURCE_DIR" = "" ] || [ "$RELEASE_ZIP" = "" ] || die "choose --source OR --release, not both"

# ---------------------------------------------------------------- deps
log "installing build deps"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq build-essential cmake pkg-config libgmp-dev openssl
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm --needed base-devel cmake gmp openssl
else
    die "unsupported package manager (need apt or pacman)"
fi

# ---------------------------------------------------------------- node user
getent passwd "$VX_USER" >/dev/null || useradd --system --home-dir "$VX_HOME" --shell /usr/sbin/nologin "$VX_USER"
mkdir -p "$VX_HOME" "$ETC" "$BIN"
chown root:"$VX_GROUP" "$VX_HOME"
chmod 750 "$VX_HOME"

# ---------------------------------------------------------------- source
SRC=$(mktemp -d /tmp/vxsrc.XXXXXX)
trap 'rm -rf "$SRC"' EXIT
if [ -n "$RELEASE_ZIP" ]; then
    [ -f "$RELEASE_ZIP" ] || die "release zip not found: $RELEASE_ZIP"
    unzip -q "$RELEASE_ZIP" -d "$SRC"
    BUILD_DIR=$(find "$SRC" -maxdepth 1 -type d -name 'vx-main-*' | head -1)
    [ -n "$BUILD_DIR" ] || die "zip layout unexpected"
else
    [ -d "$SOURCE_DIR" ] || die "source dir not found: $SOURCE_DIR"
    cp -a "$SOURCE_DIR/." "$SRC/vx/"
    BUILD_DIR="$SRC/vx"
fi

# ---------------------------------------------------------------- build
log "building vx_node (release, -j$(nproc))"
cmake -S "$BUILD_DIR" -B "$SRC/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$SRC/build" --target vx_node -j"$(nproc)"
install -m 0755 "$SRC/build/vx_node" "$BIN/vx_node"
log "installed $BIN/vx_node (version: $("$BIN/vx_node" --version 2>&1 | head -1 || true))"

# ---------------------------------------------------------------- token
if [ ! -f "$ETC/rpc-token" ]; then
    openssl rand -hex 32 > "$ETC/rpc-token"
    chmod 600 "$ETC/rpc-token"; chown root:root "$ETC/rpc-token"
    log "generated RPC token: $ETC/rpc-token"
else
    log "RPC token already exists - kept"
fi

# ---------------------------------------------------------------- peers
EXTRA_ARGS=""
if [ -n "$PEERS" ]; then
    for p in ${PEERS//,/ }; do
        EXTRA_ARGS="$EXTRA_ARGS --peer=$p"
    done
fi

# ---------------------------------------------------------------- unit
cat > /etc/systemd/system/vx-node.service <<UNIT
[Unit]
Description=VX node (validator index $INDEX)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$VX_USER
Group=$VX_GROUP
ExecStart=$BIN/vx_node --serve --p2p $P2P_PORT --data-dir $VX_HOME/data $EXTRA_ARGS
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
StateDirectory=vx
ReadWritePaths=$VX_HOME/data
EnvironmentFile=$ETC/node.env
UNIT

# ---------------------------------------------------------------- env file
if [ ! -f "$ETC/node.env" ]; then
    printf 'VX_RPC_TOKEN_FILE=%s\n' "$ETC/rpc-token" > "$ETC/node.env"
    chmod 640 "$ETC/node.env"; chown root:$VX_GROUP "$ETC/node.env"
fi

# ---------------------------------------------------------------- monit
cat > /etc/monit.d/vx-node.monit <<MONIT
check program vxnode_health with path "/bin/systemctl is-active vx-node"
  if status != 0 then alert
  if 3 restarts within 5 cycles then alert
MONIT
monit reload 2>/dev/null || true

# ---------------------------------------------------------------- firewall
# Fail-closed: only SSH + P2P. RPC stays reachable via SSH tunnel only.
if command -v ufw >/dev/null 2>&1; then
    ufw default deny incoming
    ufw allow "${SSH_PORT:-22}/tcp"
    ufw allow "${P2P_PORT}/tcp"
    ufw --force enable
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-port="${P2P_PORT}/tcp"
    firewall-cmd --reload
else
    log "no firewall tool found - verify SSH-only+P2P policy manually"
fi

# ---------------------------------------------------------------- final
systemctl daemon-reload
systemctl enable vx-node.service
log "setup complete (validator index $INDEX)"
log "next: owner provisions the validator key in the P4 phase (offline master key)"
log "check: systemctl status vx-node; journalctl -u vx-node -f"
log "RPC: ssh -L 8088:127.0.0.1:$RPC_PORT user@this-vps (token in /etc/vx/rpc-token)"
