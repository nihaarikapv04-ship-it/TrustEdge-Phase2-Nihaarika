#!/usr/bin/env bash
# Back up existing Pi/host network and firewall configuration BEFORE TrustEdge deploy.
# Read-only copy of configs into a timestamped directory. Does not change live state.
#
# Usage (on the Pi, as root):
#   sudo ./backup_host_network.sh [/var/backups/trustedge-predeploy]
set -euo pipefail

DEST_ROOT="${1:-/var/backups/trustedge-predeploy}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="${DEST_ROOT}/${STAMP}"
mkdir -p "$OUT"

echo "Backing up host network/firewall state → $OUT"

copy_if() {
  local src="$1"
  if [[ -e "$src" ]]; then
    mkdir -p "$OUT$(dirname "$src")"
    cp -a "$src" "$OUT$src" 2>/dev/null || cp -a "$src" "$OUT/"
    echo "  + $src"
  fi
}

# Kernel / routing snapshot
{
  echo "# captured $STAMP"
  uname -a
  echo
  ip -br link || true
  echo
  ip -br addr || true
  echo
  ip route || true
  echo
  ip -6 route || true
} >"$OUT/ip_snapshot.txt"

sysctl -a 2>/dev/null | grep -E 'ip_forward|rp_filter|proxy_arp|bridge' >"$OUT/sysctl_net.txt" || true

# nft / iptables
if command -v nft >/dev/null 2>&1; then
  nft list ruleset >"$OUT/nft_ruleset.txt" 2>/dev/null || echo "nft list failed" >"$OUT/nft_ruleset.txt"
fi
if command -v iptables-save >/dev/null 2>&1; then
  iptables-save >"$OUT/iptables-save.txt" 2>/dev/null || true
  iptables -L DOCKER-USER -n -v >"$OUT/iptables_DOCKER-USER.txt" 2>/dev/null || true
fi
if command -v ip6tables-save >/dev/null 2>&1; then
  ip6tables-save >"$OUT/ip6tables-save.txt" 2>/dev/null || true
fi

# Common config paths (copy if present)
for p in \
  /etc/nftables.conf \
  /etc/sysctl.conf \
  /etc/sysctl.d \
  /etc/dnsmasq.conf \
  /etc/dnsmasq.d \
  /etc/NetworkManager/system-connections \
  /etc/systemd/system/trustedge.service \
  /etc/systemd/system/trustedge-network.service \
  /etc/trustedge \
  /etc/trustedge.env \
  /etc/dhcpcd.conf \
  /etc/netplan
do
  copy_if "$p"
done

# Docker network metadata (lab)
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker network ls >"$OUT/docker_networks.txt" 2>/dev/null || true
  docker network inspect lab_lan lab_wan >"$OUT/docker_lab_networks.json" 2>/dev/null || true
fi

# SQLite / app state if already installed
if [[ -d /var/lib/trustedge ]]; then
  mkdir -p "$OUT/var_lib_trustedge"
  cp -a /var/lib/trustedge/. "$OUT/var_lib_trustedge/" 2>/dev/null || true
  echo "  + /var/lib/trustedge (copied)"
fi

chmod -R go-rwx "$OUT" 2>/dev/null || true
echo "Backup complete: $OUT"
echo "Restore is manual — compare files and re-apply carefully; do not blindly overwrite live nft."
