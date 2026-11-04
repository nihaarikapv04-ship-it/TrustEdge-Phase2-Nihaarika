#!/bin/bash
# Force default route through the TrustEdge firewall LAN address.
# Docker user-defined bridges always install gateway *.1 (host bridge). That
# path can reach the WAN bridge via HOST forwarding and BYPASS the firewall
# container — so capture sees nothing. Devices MUST use 172.20.0.2.
set -euo pipefail

GW="${TRUSTEDGE_GATEWAY_IP:-172.20.0.2}"
BRIDGE_GW="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $3; exit}')"

echo "[route] Ensuring default via TrustEdge firewall ${GW} (docker bridge was ${BRIDGE_GW:-none})"

# Prefer replace; also delete any competing defaults (Docker *.1).
ip route del default 2>/dev/null || true
ip route add default via "$GW" || ip route replace default via "$GW"

# Verify ARP/neighbours can resolve the firewall; fail loud if not.
if ! ip route get 1.1.1.1 2>/dev/null | grep -q "via ${GW}"; then
  # 1.1.1.1 may not exist in lab; also accept any default via GW
  if ! ip route show default | grep -q "via ${GW}"; then
    echo "[route] FATAL: default route is not via ${GW}" >&2
    ip route >&2
    exit 1
  fi
fi

# Continuous enforcement: Docker or netns events can reinstall *.1.
(
  while true; do
    sleep 5
    cur="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $3; exit}')"
    if [[ "$cur" != "$GW" ]]; then
      echo "[route] watchdog: default was via ${cur:-none}; restoring ${GW}"
      ip route del default 2>/dev/null || true
      ip route replace default via "$GW" 2>/dev/null || true
    fi
  done
) &
