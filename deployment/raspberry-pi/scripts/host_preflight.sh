#!/usr/bin/env bash
# Read-only host networking preflight for Raspberry Pi / Linux Engine.
# Checks DOCKER-USER, IP forwarding, nftables, NAT, and Docker bridge topology.
# Does NOT modify interfaces, iptables, nft, or Docker. Safe to run anytime.
#
# Usage (on the Pi or Linux lab host):
#   sudo ./host_preflight.sh              # full report; exit 1 if critical fail
#   sudo ./host_preflight.sh --lab        # also inspect lab_lan / lab_wan bridges
#   ./host_preflight.sh --prod            # production eth expectations (default)
set -euo pipefail

MODE=prod
STRICT=1
for arg in "$@"; do
  case "$arg" in
    --lab) MODE=lab ;;
    --prod) MODE=prod ;;
    --soft) STRICT=0 ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

PASS=0
WARN=0
FAIL=0
note() { printf '  %-10s %s\n' "$1" "$2"; }
ok()   { note PASS "$1"; PASS=$((PASS+1)); }
warn() { note WARN "$1"; WARN=$((WARN+1)); }
bad()  { note FAIL "$1"; FAIL=$((FAIL+1)); }

echo "=== TrustEdge host preflight ($(date -u +%Y-%m-%dT%H:%MZ)) mode=$MODE ==="
echo

echo "== architecture / OS =="
ARCH=$(uname -m)
OS=$(uname -s)
note INFO "uname: $OS $ARCH"
if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
  ok "architecture is 64-bit ARM ($ARCH)"
else
  warn "architecture is $ARCH (Pi production expects aarch64)"
fi
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  note INFO "os-release: ${PRETTY_NAME:-unknown}"
fi

echo
echo "== Docker Engine (optional; required for lab-on-Pi only) =="
if command -v docker >/dev/null 2>&1; then
  ok "docker CLI present: $(docker --version 2>/dev/null | head -1)"
  if docker info >/dev/null 2>&1; then
    ok "docker daemon reachable"
    note INFO "server arch: $(docker info --format '{{.Architecture}}' 2>/dev/null || echo '?')"
  else
    warn "docker daemon not reachable (OK for native production)"
  fi
else
  note INFO "docker not installed (OK for native production gateway)"
fi

echo
echo "== physical / host interfaces (inspect only) =="
if command -v ip >/dev/null 2>&1; then
  ip -br link || true
  echo
  ip -br addr || true
  echo
  echo "-- default route --"
  ip route show default || warn "no default route"
  if [[ "$MODE" == prod ]]; then
    for ifc in eth0 eth1; do
      if ip link show "$ifc" >/dev/null 2>&1; then
        ok "interface $ifc exists"
      else
        warn "interface $ifc not present (USB NIC may be enx… — confirm before deploy)"
      fi
    done
  fi
else
  bad "iproute2 (ip) missing"
fi

echo
echo "== IPv4 forwarding =="
FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo missing)
note INFO "net.ipv4.ip_forward=$FWD"
if [[ "$MODE" == prod ]]; then
  if [[ "$FWD" == "1" ]]; then
    ok "IP forwarding enabled"
  else
    warn "IP forwarding is $FWD (trustedge-network.service enables it at start)"
  fi
else
  note INFO "lab mode: forwarding may be enabled inside the firewall container"
fi

echo
echo "== nftables =="
if command -v nft >/dev/null 2>&1; then
  ok "nft present: $(nft --version 2>/dev/null | head -1)"
  if nft list tables >/dev/null 2>&1; then
    note INFO "tables:"
    nft list tables 2>/dev/null | sed 's/^/    /' || true
    if nft list table inet trustedge >/dev/null 2>&1; then
      ok "table inet trustedge present"
      FWD_RULES=$(nft list chain inet trustedge forward 2>/dev/null | wc -l | tr -d ' ')
      note INFO "forward chain lines≈$FWD_RULES"
    else
      warn "inet trustedge not loaded yet (expected before first deploy)"
    fi
    if nft list table ip trustedge_nat >/dev/null 2>&1; then
      ok "table ip trustedge_nat present"
      if nft list table ip trustedge_nat 2>/dev/null | grep -q masquerade; then
        ok "NAT masquerade rule present in trustedge_nat"
      else
        warn "trustedge_nat present but no masquerade visible"
      fi
    else
      warn "ip trustedge_nat not loaded yet (expected before first deploy)"
    fi
  else
    warn "nft list tables failed (need root?)"
  fi
else
  bad "nftables (nft) missing — required on Pi"
fi

echo
echo "== iptables DOCKER-USER (lab bridge isolation) =="
if command -v iptables >/dev/null 2>&1; then
  if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    ok "DOCKER-USER chain exists"
    echo "-- DOCKER-USER rules (packet counters) --"
    iptables -L DOCKER-USER -n -v 2>/dev/null | sed 's/^/    /' || true
    DROP_COUNT=$(iptables -L DOCKER-USER -n 2>/dev/null | grep -c DROP || true)
    if [[ "$MODE" == lab ]]; then
      if [[ "${DROP_COUNT:-0}" -gt 0 ]]; then
        ok "DOCKER-USER has DROP rules (lab bridge bypass likely blocked)"
      else
        warn "DOCKER-USER has no DROP rules — host may forward lab_lan↔lab_wan around the firewall"
        note INFO "review: deployment/raspberry-pi/scripts/block_docker_bridge_bypass.sh"
      fi
    else
      note INFO "production uses nft on eth0/eth1; DOCKER-USER only matters for optional lab-on-Pi"
    fi
  else
    if [[ "$MODE" == lab ]]; then
      warn "DOCKER-USER chain missing (Docker may not be using iptables legacy)"
    else
      note INFO "DOCKER-USER absent (OK when Docker unused)"
    fi
  fi
else
  note INFO "iptables not installed"
fi

echo
echo "== Docker bridges / lab networks =="
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker network ls --format 'table {{.Name}}\t{{.Driver}}\t{{.Scope}}' 2>/dev/null | sed 's/^/    /' || true
  if [[ "$MODE" == lab ]]; then
    for net in lab_lan lab_wan; do
      if docker network inspect "$net" >/dev/null 2>&1; then
        ok "docker network $net exists"
        BR=$(docker network inspect "$net" -f '{{.Id}}' 2>/dev/null | cut -c1-12)
        note INFO "$net id-prefix=$BR (bridge ifname often br-$BR)"
        GW=$(docker network inspect "$net" -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)
        SUB=$(docker network inspect "$net" -f '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null || true)
        note INFO "$net subnet=$SUB gateway=$GW"
        # Detect host bridge bypass risk: both bridges up and forwarding on
        if [[ -n "$BR" ]] && ip link show "br-$BR" >/dev/null 2>&1; then
          note INFO "host bridge iface br-$BR is UP"
        fi
      else
        warn "docker network $net not found (start lab compose first)"
      fi
    done
    # Device default GW reminder
    note INFO "device containers MUST use default via 172.20.0.2 (not .1)"
  fi
else
  note INFO "skip docker network inspect"
fi

echo
echo "== sysctl rp_filter / proxy_arp (informational) =="
for k in net.ipv4.conf.all.rp_filter net.ipv4.conf.all.forwarding; do
  note INFO "$k=$(sysctl -n "$k" 2>/dev/null || echo n/a)"
done

echo
echo "== summary =="
echo "  PASS=$PASS  WARN=$WARN  FAIL=$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
  if [[ "$STRICT" -eq 1 ]]; then
    echo "CRITICAL checks failed."
    exit 1
  fi
  echo "Completed with FAIL=$FAIL under --soft (expected on non-Pi hosts)."
  exit 0
fi
if [[ "$WARN" -gt 0 ]]; then
  echo "Completed with warnings — review before changing the Pi."
  exit 0
fi
echo "All critical checks passed."
exit 0
