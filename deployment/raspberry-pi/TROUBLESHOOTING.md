# Troubleshooting Pi / Docker networking

## Symptom: firewall “learns” but not from device containers

### Primary root cause (proven)

Docker installs **default gateway `172.20.0.1`** (host bridge) on every lab device.  
TrustEdge capture only sees forwarded traffic when the default is **`172.20.0.2`** (firewall).

On Raspberry Pi **Linux Engine**, the host often **forwards `lab_lan`↔`lab_wan` itself**. Devices then reach WAN services while **bypassing** the firewall namespace — so Scapy on the firewall LAN iface never gets their packets.

**Fix in tree:** `lab/containers/_common/ensure_gateway.sh` (mounted into every device) deletes `*.1`, sets `via 172.20.0.2`, and watches every 5s. Prove with:

```sh
./lab/scripts/prove_firewall_path.sh
```

Optional host hardening (lab-on-Pi only):  
`deployment/raspberry-pi/scripts/block_docker_bridge_bypass.sh --check` then `--apply` after review.

Read-only host audit (DOCKER-USER, forwarding, nft, NAT, bridges):  
`deployment/raspberry-pi/scripts/host_preflight.sh --lab` (or `--prod`).

Do **not** run native eth0/eth1 TrustEdge production and the Docker lab on the same Pi without isolating them — physical nft and Docker bridges can interact badly.

Full write-up: `docs/FIREWALL_PATH_REPORT.md`.

### Other established causes

1. **Split LAN/WAN bridges** — devices only on `lab_lan`; WAN services on `lab_wan`; firewall on both. A flat single bridge is wrong for this design.

2. **`localhost` inside a container** — never a peer path; use `172.21.0.x` / env `TRUSTEDGE_*_IP`.

3. **API bind** — production `127.0.0.1`; lab `TRUSTEDGE_LAB_BIND=1` + `0.0.0.0`.

4. **Startup races** — devices wait for firewall healthcheck.

5. **Orphan networks** — remove empty leftovers (`docker network ls`); do not keep conflicting `172.20/172.21` owners.

6. **Interface flip** — firewall entrypoint resolves LAN/WAN **by IP**, not by assuming eth0=LAN.

## Quick probes

```sh
docker exec trustedge-lab-laptop ip route
# must show: default via 172.20.0.2
docker exec trustedge-lab-laptop curl -s -o /dev/null -w '%{http_code}\n' http://172.21.0.10/
docker exec trustedge-lab-firewall nft list table inet trustedge | head
./lab/scripts/prove_firewall_path.sh
./lab/scripts/comm_smoke_test.sh
```

## Production (native) failures

| Symptom | Check |
| --- | --- |
| No DHCP on IoT LAN | dnsmasq config, `eth1` address, conflicting DHCP |
| Dashboard unreachable | SSH tunnel to `127.0.0.1:8080`; API must not be exposed on WAN |
| Devices bypass Pi | Clients still associated to upstream Wi-Fi |
| nft apply failed | `journalctl -u trustedge`; policy transaction rolled back |

## ARM64 notes

- Base images: `python:3.11-slim` and `coredns/coredns` publish arm64 manifests.
- Scapy needs `libpcap0.8` in the image/OS.
- sklearn `1.6.1` installs from wheels on aarch64.
- Building on Mac for Pi: `docker buildx build --platform linux/arm64 ...`
