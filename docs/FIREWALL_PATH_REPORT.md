# Device → Firewall path investigation and fix

**Date:** 2026-11-04  
**Workspace:** `~/cursor/trustedge-phase2-integration`  
**Physical Pi:** not modified  
**Git push:** none  

## Symptom (Pi)

Firewall container runs and appears to “learn,” but laptop/camera/thermostat/phone/printer traffic does not feed capture/detection. Supporting WAN containers exist, yet device packets never traverse TrustEdge.

## Root cause (proven locally)

Docker user-defined bridges install **default gateway `172.20.0.1`** (host bridge), not the firewall container (`172.20.0.2`).

| Default gateway | WAN HTTP | Packets on firewall LAN (`tcpdump eth0 host <device> and net 172.21.0.0/24`) |
| --- | --- | --- |
| **172.20.0.2** (TrustEdge) | Works when permitted | **Captured** (e.g. 30 packets / RX delta ≫ 0) |
| **172.20.0.1** (Docker bridge) | May still work on Linux Engine if the **host** forwards `lab_lan`↔`lab_wan` | **Zero** matching captures on firewall |

On Raspberry Pi Linux Engine, host forwarding between the two bridges is common — devices look “online” while **bypassing** the firewall namespace. Capture then only sees incidental local/firewall traffic (“learning its own traffic”).

Earlier `ip route replace … via 172.20.0.2 2>/dev/null || true` was silent on failure and did not re-apply if Docker reinstalled `*.1`.

### Answers to architecture checklist

| # | Question | Answer |
| --- | --- | --- |
| 1 | Same Docker network as firewall LAN? | Yes — all devices on `lab_lan` with firewall |
| 2 | Using firewall as default gateway? | **Must** — `172.20.0.2`; Docker default is wrongly `*.1` |
| 3 | Via Docker bridge instead of TrustEdge? | **Yes — the Pi failure mode** when gw=`*.1` |
| 4 | Separate bridges LAN vs WAN? | Yes — intentional segmentation |
| 5 | Firewall on LAN + WAN? | Yes — `172.20.0.2` + `172.21.0.2` |
| 6 | IP forwarding in firewall? | Yes (`sysctl` + compose) |
| 7 | Routes correct? | Only after `ensure_gateway.sh` |
| 8 | nftables forward? | Yes — single `inet trustedge` engine |
| 9 | NAT? | `ip trustedge_nat` masquerade on WAN iface |
| 10 | Scapy iface? | LAN iface resolved by IP (eth0 when `172.20.0.2`) |
| 11 | Bypass firewall? | Yes if gw=`*.1` + host forward |
| 12 | Physical eth0/eth1 conflict? | Separate from lab bridges; running native Pi gateway **and** lab Compose on one host can compete — keep modes separate |

East-west (device↔device on `lab_lan`) is L2-switched on the bridge and **does not** hairpin through the firewall unless hairpin routing is added. Not claimed as inspected.

## Fixes applied (local)

1. `lab/containers/_common/ensure_gateway.sh` — delete competing defaults, set `via 172.20.0.2`, **watchdog** every 5s  
2. All device `traffic_gen.sh` source that script (fail loud)  
3. Compose mounts the script; `enable_ip_masquerade: false` on lab bridges  
4. Firewall entrypoint: `rp_filter=0`, `proxy_arp` on LAN, forwarding  
5. `lab/scripts/prove_firewall_path.sh` — per-device gateway + tcpdump + RX counters + quarantine contrast  
6. Pi helper notes: `deployment/raspberry-pi/scripts/block_docker_bridge_bypass.sh`  
7. Removed empty orphan networks `trustedge_lan` / `trustedge_wan` (unused, wrong subnets)

## Evidence (macOS Docker integration, 2026-11-04)

Artifact: `lab/results/firewall_path_proof.txt`

| Container | IP | Network | Gateway | Capture on fw LAN | HTTP via TrustEdge |
| --- | --- | --- | --- | --- | --- |
| laptop | 172.20.0.10 | lab_lan | 172.20.0.2 | PASS (SYN to WAN seen; nft drop while QUARANTINE) | blocked |
| iot-camera | 172.20.0.11 | lab_lan | 172.20.0.2 | PASS | blocked (QUARANTINE) |
| iot-thermostat | 172.20.0.12 | lab_lan | 172.20.0.2 | PASS (full HTTP 200 exchange) | 200 |
| phone | 172.20.0.13 | lab_lan | 172.20.0.2 | PASS | blocked (QUARANTINE) |
| printer | 172.20.0.14 | lab_lan | 172.20.0.2 | PASS | blocked (QUARANTINE) |

Controlled contrast: TRUSTED thermostat HTTP 200; QUARANTINE laptop HTTP not 200 — same nft engine.

**Not a physical Raspberry Pi test.**

## Physical Pi vs Docker lab

| Mode | Networking |
| --- | --- |
| **Production Pi** | Native process on `eth0` WAN + `eth1` LAN; no device containers |
| **Lab-on-Pi** | This Compose dual-bridge topology only; do not also enable host forwarding between lab bridges; do not reuse `192.168.50.0/24` physical subnet for `172.20/172.21` lab nets |

## Cleanup

| Action | Reason |
| --- | --- |
| Removed Docker networks `trustedge_lan`, `trustedge_wan` | Empty, unused, conflicting leftovers |
| `docker compose down` (no `-v`) + up | Recreate bridges with new driver_opts; **lab-db volume retained** |
| Retained all source, models, SQLite volume, deploy scripts | Still referenced |
| No `docker system prune --volumes` | Forbidden / would destroy lab state |
