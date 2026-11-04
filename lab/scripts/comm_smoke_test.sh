#!/usr/bin/env bash
# Container-to-container communication smoke test for the TrustEdge lab.
# Demonstrates DNS names, TCP, and HTTP — not merely "container is Up".
set -euo pipefail

FW=trustedge-lab-firewall
PASS=0
FAIL=0

check() {
  local name="$1"
  shift
  echo -n "  [$name] "
  if "$@" >/tmp/te_comm_out.txt 2>/tmp/te_comm_err.txt; then
    echo "OK $(tr '\n' ' ' </tmp/te_comm_out.txt | head -c 120)"
    PASS=$((PASS + 1))
  else
    echo "FAIL"
    cat /tmp/te_comm_err.txt >&2 || true
    cat /tmp/te_comm_out.txt >&2 || true
    FAIL=$((FAIL + 1))
  fi
}

echo "=== TrustEdge lab communication smoke test ==="
echo "Firewall routes LAN(172.20/24) ↔ WAN(172.21/24); devices must not use localhost for peers."

# DNS aliases from firewall (on both networks)
check "fw resolves webserver" docker exec "$FW" getent hosts webserver
check "fw resolves wan-sink" docker exec "$FW" getent hosts wan-sink
check "fw resolves dns" docker exec "$FW" getent hosts dns
check "fw resolves laptop" docker exec "$FW" getent hosts laptop

# TCP/HTTP from firewall to WAN services (same L2 WAN bridge)
check "fw HTTP webserver:80" docker exec "$FW" curl -sf --max-time 5 http://172.21.0.10/ -o /dev/null
check "fw HTTP wan-sink:/ping" docker exec "$FW" curl -sf --max-time 5 http://172.21.0.11/ping -o /dev/null
check "fw DNS UDP/53 open" docker exec "$FW" python3 -c \
  'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b"\x00",("172.21.0.12",53));print("sent")'

# Device default routes (all devices)
for c in trustedge-lab-laptop trustedge-lab-iot-camera trustedge-lab-iot-thermostat \
         trustedge-lab-phone trustedge-lab-printer; do
  check "$c default via 172.20.0.2" docker exec "$c" sh -c \
    'ip route | grep -E "default via 172\.20\.0\.2"'
done

# HTTP via gateway — only assert success for devices that are not QUARANTINE.
# Quarantine correctly blocks HTTP; that is enforcement, not a networking failure.
token_cmd='import os,json,urllib.request;t=os.environ["TRUSTEDGE_API_TOKEN"];d=json.load(urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8080/status",headers={"Authorization":"Bearer "+t}),timeout=5));print({x["ip"]:x["desired_tier"] for x in d["devices"]})'
tiers=$(docker exec "$FW" python3 -c "$token_cmd")
echo "  device tiers: $tiers"

expect_http() {
  local ip="$1" c="$2" path="$3"
  if echo "$tiers" | grep -q "'$ip': 'QUARANTINE'"; then
    echo -n "  [$c HTTP blocked while QUARANTINE] "
    if docker exec "$c" curl -sf --max-time 3 "$path" -o /dev/null; then
      echo "FAIL (unexpected success)"
      FAIL=$((FAIL + 1))
    else
      echo "OK (blocked as designed)"
      PASS=$((PASS + 1))
    fi
  else
    check "$c HTTP→$path via GW" docker exec "$c" curl -sf --max-time 5 "$path" -o /dev/null
  fi
}

expect_http 172.20.0.10 trustedge-lab-laptop http://172.21.0.10/
expect_http 172.20.0.11 trustedge-lab-iot-camera http://172.21.0.10/
expect_http 172.20.0.11 trustedge-lab-iot-camera http://172.21.0.11/ping
expect_http 172.20.0.12 trustedge-lab-iot-thermostat http://172.21.0.11/ping
expect_http 172.20.0.13 trustedge-lab-phone http://172.21.0.10/
expect_http 172.20.0.14 trustedge-lab-printer http://172.21.0.10/

# DNS via firewall datapath (UDP/53 to lab DNS) — QUARANTINE and TRUSTED both allow DNS
dns_probe() {
  local c="$1"
  docker exec "$c" python3 -c \
    'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",("172.21.0.12",53));r=s.recv(512);print("dns_bytes",len(r)); assert len(r)>0'
}
for c in trustedge-lab-laptop trustedge-lab-iot-camera trustedge-lab-iot-thermostat \
         trustedge-lab-phone trustedge-lab-printer; do
  check "$c DNS UDP/53 via GW→172.21.0.12" dns_probe "$c"
done

# Negative: device must NOT reach WAN service via localhost
check "laptop localhost≠webserver" docker exec trustedge-lab-laptop sh -c \
  '! curl -sf --max-time 2 http://127.0.0.1/ >/dev/null'

# Isolation: quarantined laptop HTTP blocked while TRUSTED thermostat still works
if echo "$tiers" | grep -q "'172.20.0.10': 'QUARANTINE'" && echo "$tiers" | grep -q "'172.20.0.12': 'TRUSTED'"; then
  echo -n "  [isolation laptop HTTP blocked] "
  if docker exec trustedge-lab-laptop curl -sf --max-time 3 http://172.21.0.10/ -o /dev/null; then
    echo "FAIL (laptop unexpectedly allowed)"
    FAIL=$((FAIL + 1))
  else
    echo "OK"
    PASS=$((PASS + 1))
  fi
  check "isolation thermo HTTP allowed" docker exec trustedge-lab-iot-thermostat \
    curl -sf --max-time 5 http://172.21.0.11/ping -o /dev/null
else
  echo "  [isolation pair] SKIP (need laptop QUARANTINE + thermo TRUSTED; tiers=$tiers)"
fi

# API published ports from host network namespace (via firewall container loopback)
check "API listens :8080" docker exec "$FW" sh -c \
  'code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/status || true); echo $code | grep -Eq "401|200"'

# Forwarding + nft present
check "ip_forward=1" docker exec "$FW" sh -c 'test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1'
check "nft trustedge table" docker exec "$FW" nft list table inet trustedge >/dev/null
check "nft NAT masquerade" docker exec "$FW" sh -c 'nft list table ip trustedge_nat | grep -q masquerade'

echo
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo "All communication checks passed."
