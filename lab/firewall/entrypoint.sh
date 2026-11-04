#!/bin/bash
# Bootstrap deny + NAT, then start the Phase 2 live gateway inside the lab firewall.
set -euo pipefail

TOKEN="${TRUSTEDGE_API_TOKEN:-}"
if [[ ${#TOKEN} -lt 24 ]]; then
  echo "[lab-firewall] TRUSTEDGE_API_TOKEN must be at least 24 characters" >&2
  exit 1
fi

LAN_IP="${TRUSTEDGE_LAN_IP:-172.20.0.2}"
WAN_IP="${TRUSTEDGE_WAN_IP:-172.21.0.2}"
SUBNET="${TRUSTEDGE_SUBNET:-172.20.0.0/24}"
DNS_IP="${TRUSTEDGE_DNS_IP:-172.21.0.12}"
DATABASE="${TRUSTEDGE_DATABASE:-/var/lib/trustedge/lab.sqlite}"
PORT="${TRUSTEDGE_API_PORT:-8080}"

echo "[lab-firewall] Resolving LAN/WAN interfaces for ${LAN_IP} / ${WAN_IP}..."
LAN_IF="$(ip -o addr show | awk -v ip="$LAN_IP" '$0 ~ ip "/" {print $2; exit}')"
WAN_IF="$(ip -o addr show | awk -v ip="$WAN_IP" '$0 ~ ip "/" {print $2; exit}')"
if [[ -z "$LAN_IF" || -z "$WAN_IF" || "$LAN_IF" == "$WAN_IF" ]]; then
  echo "[lab-firewall] could not resolve distinct LAN/WAN interfaces" >&2
  ip -br addr >&2 || true
  exit 1
fi
echo "[lab-firewall] LAN=${LAN_IF} WAN=${WAN_IF}"

echo "[lab-firewall] Installing bootstrap deny rules before forwarding..."
# tcp dport API accept must live in this same input chain (before LAN drop).
# A separate table's accept does not override a later drop in inet trustedge.
nft delete table inet trustedge_lab_mgmt 2>/dev/null || true
nft delete table inet trustedge 2>/dev/null || true
nft -f - <<EOF
table inet trustedge {
  chain input {
    type filter hook input priority -10; policy accept;
    tcp dport ${PORT} accept
    iifname "${LAN_IF}" meta nfproto ipv6 drop
    iifname "${LAN_IF}" drop
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "${LAN_IF}" meta nfproto ipv6 drop
    oifname "${LAN_IF}" meta nfproto ipv6 drop
    iifname "${LAN_IF}" ip saddr != ${SUBNET} drop
    iifname "${LAN_IF}" drop
    oifname "${LAN_IF}" drop
  }
}
EOF

echo "[lab-firewall] Installing NAT masquerade on ${WAN_IF}..."
nft delete table ip trustedge_nat 2>/dev/null || true
nft -f - <<EOF
table ip trustedge_nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "${WAN_IF}" masquerade
  }
}
EOF

# Compose already sets net.ipv4.ip_forward=1; /proc write is often read-only in containers.
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
# Loose rp_filter so forwarded LAN→WAN replies are not dropped asymmetrically.
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done
# Answer ARP for our LAN IP as the device default gateway.
echo 1 > "/proc/sys/net/ipv4/conf/${LAN_IF}/proxy_arp" 2>/dev/null || true
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding 2>/dev/null || true

echo "[lab-firewall] Starting Phase 2 gateway (live capture on ${LAN_IF})..."
exec python -m trustedge \
  --mode live \
  --database "$DATABASE" \
  --lan "$LAN_IF" \
  --wan "$WAN_IF" \
  --subnet "$SUBNET" \
  --dns "$DNS_IP" \
  --port "$PORT" \
  --bind 0.0.0.0
