#!/usr/bin/env bash
# Optional HOST helper for Linux Engine / Raspberry Pi lab-on-Pi.
# Drops direct HOST forwarding between TrustEdge lab bridges so the only
# LAN→WAN path is through the firewall container (172.20.0.2).
#
# Does NOT modify physical eth0/eth1 TrustEdge production rules.
# Review before applying. Not run automatically.
#
# Usage:
#   ./block_docker_bridge_bypass.sh           # print guidance + auto-detect
#   ./block_docker_bridge_bypass.sh --check   # detect bridges / DOCKER-USER only
#   ./block_docker_bridge_bypass.sh --apply   # insert DROP rules (requires root)
set -euo pipefail

ACTION=guide
for arg in "$@"; do
  case "$arg" in
    --check) ACTION=check ;;
    --apply) ACTION=apply ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
  esac
done

detect_bridges() {
  LAN_BR=""
  WAN_BR=""
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker not available" >&2
    return 1
  fi
  if ! docker network inspect lab_lan >/dev/null 2>&1; then
    echo "lab_lan network missing — start Compose first" >&2
    return 1
  fi
  if ! docker network inspect lab_wan >/dev/null 2>&1; then
    echo "lab_wan network missing — start Compose first" >&2
    return 1
  fi
  LAN_ID=$(docker network inspect lab_lan -f '{{.Id}}' | cut -c1-12)
  WAN_ID=$(docker network inspect lab_wan -f '{{.Id}}' | cut -c1-12)
  # Docker bridge ifname is typically br-<12-hex>
  for cand in "br-$LAN_ID"; do
    if ip link show "$cand" >/dev/null 2>&1; then LAN_BR=$cand; fi
  done
  for cand in "br-$WAN_ID"; do
    if ip link show "$cand" >/dev/null 2>&1; then WAN_BR=$cand; fi
  done
  # Fallback: scan bridge names containing id prefix
  if [[ -z "$LAN_BR" ]]; then
    LAN_BR=$(ip -o link | awk -F': ' -v id="$LAN_ID" '$2 ~ id {print $2; exit}')
  fi
  if [[ -z "$WAN_BR" ]]; then
    WAN_BR=$(ip -o link | awk -F': ' -v id="$WAN_ID" '$2 ~ id {print $2; exit}')
  fi
  echo "lab_lan id=$LAN_ID bridge=${LAN_BR:-NOT_FOUND}"
  echo "lab_wan id=$WAN_ID bridge=${WAN_BR:-NOT_FOUND}"
}

echo "=== Docker bridge bypass helper ==="
detect_bridges || true

echo
echo "-- DOCKER-USER (current) --"
if command -v iptables >/dev/null 2>&1 && iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  iptables -L DOCKER-USER -n -v || true
else
  echo "DOCKER-USER not available (need root + iptables + Docker)"
fi

if [[ "$ACTION" == check || "$ACTION" == guide ]]; then
  echo
  echo "Device containers must still use default via 172.20.0.2 (ensure_gateway.sh)."
  echo "Prove path: lab/scripts/prove_firewall_path.sh"
  if [[ "$ACTION" == guide ]]; then
    echo
    echo "To apply (after review), re-run with --apply as root:"
    cat <<EOF
  sudo iptables -C DOCKER-USER -i ${LAN_BR:-br-LAN} -o ${WAN_BR:-br-WAN} -j DROP 2>/dev/null \\
    || sudo iptables -I DOCKER-USER -i ${LAN_BR:-br-LAN} -o ${WAN_BR:-br-WAN} -j DROP
  sudo iptables -C DOCKER-USER -i ${WAN_BR:-br-WAN} -o ${LAN_BR:-br-LAN} -j DROP 2>/dev/null \\
    || sudo iptables -I DOCKER-USER -i ${WAN_BR:-br-WAN} -o ${LAN_BR:-br-LAN} -j DROP
  sudo iptables -L DOCKER-USER -n -v
EOF
  fi
  exit 0
fi

# --apply
if [[ "$(id -u)" -ne 0 ]]; then
  echo "--apply requires root" >&2
  exit 1
fi
if [[ -z "${LAN_BR:-}" || -z "${WAN_BR:-}" ]]; then
  echo "Could not resolve bridge ifnames; refusing to apply" >&2
  exit 1
fi
iptables -C DOCKER-USER -i "$LAN_BR" -o "$WAN_BR" -j DROP 2>/dev/null \
  || iptables -I DOCKER-USER -i "$LAN_BR" -o "$WAN_BR" -j DROP
iptables -C DOCKER-USER -i "$WAN_BR" -o "$LAN_BR" -j DROP 2>/dev/null \
  || iptables -I DOCKER-USER -i "$WAN_BR" -o "$LAN_BR" -j DROP
echo "Applied DOCKER-USER DROPs between $LAN_BR and $WAN_BR"
iptables -L DOCKER-USER -n -v
echo "Do not apply this on a host that needs unrestricted Docker inter-network routing."
