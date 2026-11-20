# VX validator runbook (P5 phase)

One `setup_validator.sh` run per machine. Templated for 4 VPS (owner
decision 19.11: prove it locally first — this runbook is for the P5
phase that follows).

## Prerequisites (owner inputs — P4/P5)

- P4: the validator list for the first epoch (which machines, which
  `node_id`s) — swaps into `src/blockchain/genesis.cpp` epoch committee
  and pins the master signature (the sk never ships).
- P5: domain + 4 VPS (Debian/Arch), SSH access, `unzip` on each.

## Per-machine procedure

1. Copy the release zip (`vx-main-<sha>.zip` from `archives/zips`,
   authenticity = the GPG tag signature) to the machine.
2. `sudo ./scripts/deploy/setup_validator.sh --index N --p2p-port 19088 \
      --peers "IP1:19088,IP2:19088" --release /path/to/vx-main-<sha>.zip`
3. The script: installs deps, builds `vx_node`, generates the RPC token
   (`/etc/vx/rpc-token`, 600), writes the hardened systemd unit
   (`vx-node.service`), monit check, firewall (SSH + P2P only — RPC via
   SSH tunnel), enables the unit.
4. Verify: `systemctl status vx-node`, `journalctl -u vx-node -f`,
   `ssh -L 8088:127.0.0.1:8088 user@vps` then
   `curl -s localhost:8088/api/health`.
5. Validator key provisioning is the P4 phase step, done separately with
   the offline master key — never inside this script.

## What this script does NOT do

- Does not hold or create any keys.
- Does not open the RPC port to the world.
- Does not replace the P4 phase (whitelist + master signature).
