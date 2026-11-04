# Raspberry Pi 4 deployment package (local preparation)

This directory prepares TrustEdge Phase 2 for **your** Raspberry Pi 4.  
Nothing here is applied to the physical Pi automatically. Copy, review, then install yourself.

## 1. Hardware and network requirements

| Item | Role |
| --- | --- |
| Raspberry Pi 4 | Gateway host (capture → IF → AE → hard rules → EWMA → nft → SQLite → `/p1` dashboard) |
| Raspberry Pi OS Lite **64-bit** (Bookworm) | Confirmed target: **aarch64 / linux/arm64** |
| Onboard Ethernet `eth0` | **WAN** toward the main router |
| USB-to-Ethernet `eth1` (name may be `enx…`) | **Protected IoT LAN** |
| Old router (optional) | AP/bridge on the IoT LAN only |
| Windows laptop | Wired test client on IoT LAN |
| Phone | Wireless test client via IoT AP |
| MacBook | Admin + SSH tunnel to dashboard |

Do **not** connect IoT clients to the upstream router LAN/Wi-Fi — that bypasses the Pi.

## 2. Interface roles

```text
Main router
    │
    eth0 (WAN)
 Raspberry Pi 4  ← TrustEdge gateway (native Python/systemd)
    eth1 (LAN 192.168.50.0/24 example)
    │
 IoT AP / switch → laptop, phone, cameras, …
```

Confirm names with `ip -br link` before editing config.

## 3. Which containers run on the Pi?

**Production (recommended):** **no Docker** for the gateway. One native process owns capture, detection, trust, nft, SQLite, and the Phase 1 dashboard (`/` and `/p1`).

**Optional lab-on-Pi:** Docker Compose dual-bridge lab (`lab/docker-compose.yml` + `docker-compose.lab-on-pi.yml`) for software topology tests. Simulated devices (laptop/camera/…) are containers; they are not your physical phone/laptop.

## 4. Service communication map

### Production

| From | To | How |
| --- | --- | --- |
| IoT devices | Internet / DNS | Routed via Pi `eth1`→`eth0`, filtered by nft |
| Admin browser | Dashboard API | SSH tunnel → `127.0.0.1:8080` (API binds loopback) |
| Gateway | nftables | Local netlink; single engine (`inet trustedge` + `ip trustedge_nat`) |

### Lab Compose

| From | To | How |
| --- | --- | --- |
| Device containers (`172.20.0.10–14`) | WAN services | Default route `172.20.0.2` (firewall) + NAT |
| Firewall | `webserver` / `wan-sink` / `dns` | Same `wan` bridge **or** DNS aliases |
| Host admin | API | Published `8080`/`5001` → firewall `0.0.0.0:8080` (lab bind only) |

Devices must **never** use `localhost`/`127.0.0.1` to reach WAN services.

## 5. Docker network topology (lab)

```text
trustedge_lab_lan  172.20.0.0/24
  laptop .10, camera .11, thermo .12, phone .13, printer .14
  firewall .2  ────────────────────────────┐
trustedge_lab_wan  172.21.0.0/24           │
  firewall .2, webserver .10, sink .11, dns .12
```

Segmentation is intentional: LAN devices only talk to WAN through the firewall container.

## 6. Required ports

| Port | Where | Purpose |
| --- | --- | --- |
| 8080/tcp | Pi loopback (prod) / published (lab) | API + dashboard |
| 5001/tcp | Lab publish alias | Phase 1 port familiarity |
| 53/udp | LAN→Pi DNS | Device name resolution |
| 67/udp | LAN DHCP | Leases (dnsmasq) |

## 7. Environment configuration

1. Copy `.env.example` → `/etc/trustedge.env` (mode `0600`).
2. Render hardware artifacts:  
   `python -m trustedge.hardware render --config deploy/pi.example.json --output build/my-pi`
3. Review `gateway.json`, `bootstrap.nft`, `nat.nft`, NetworkManager, dnsmasq, systemd units.

## 8. Staged commissioning (required before physical deploy)

Follow **`COMMISSIONING.md`** end-to-end. Summary:

0. Preserve local RC → `scripts/preserve_local_rc.sh`  
1. Inspect arch / Docker / host (`scripts/host_preflight.sh`) — **no interface changes**  
2. Inspect eth0/eth1 only  
3. Back up host network/firewall (`scripts/backup_host_network.sh`)  
4. Deploy gateway + **one** device  
5. Verify capture, nft counters, HTTP/DNS  
6. Add remaining devices  
7. Trust / quarantine / dashboard checks  
8. Reboot persistence  

Full narrative for artifact install: `docs/PI_DEPLOYMENT.md`.

## 9. Installation commands (production sketch)

```sh
# On the Pi, after copying this repo to /opt/trustedge
sudo apt-get update
sudo apt-get install -y python3 python3-venv nftables iproute2 util-linux dnsmasq libpcap0.8
cd /opt/trustedge
python3 -m venv .venv
.venv/bin/pip install .
# Install reviewed files from build/my-pi into /etc/trustedge, NM, dnsmasq, systemd
sudo cp deployment/raspberry-pi/.env.example /etc/trustedge.env  # then edit
sudo systemctl daemon-reload
sudo systemctl enable --now nftables trustedge-network trustedge
```

## 10. Startup / shutdown / rollback

```sh
sudo deployment/raspberry-pi/scripts/start.sh    # or systemctl start trustedge
sudo deployment/raspberry-pi/scripts/stop.sh
# Keep previous tree before upgrade:
sudo cp -a /opt/trustedge /opt/trustedge.prev
sudo deployment/raspberry-pi/scripts/rollback.sh /opt/trustedge.prev
```

Stopping `trustedge.service` keeps nft policy. Stopping `trustedge-network.service` disables forwarding.

Local Mac RC (not pushed): `scripts/preserve_local_rc.sh` → `rc-snapshots/` + local git tag.

## 11. Verification

```sh
sudo deployment/raspberry-pi/scripts/host_preflight.sh --prod   # or --lab
sudo deployment/raspberry-pi/scripts/validate.sh
# Lab-only container paths:
lab/scripts/prove_firewall_path.sh
lab/scripts/comm_smoke_test.sh
# Lab bridge bypass check (Linux Engine):
deployment/raspberry-pi/scripts/block_docker_bridge_bypass.sh --check
```

## 12. Log inspection

```sh
journalctl -u trustedge -u trustedge-network -f
nft list ruleset
```

## 13. Safe shutdown and recovery

1. `systemctl stop trustedge` — policy retained.  
2. To drop forwarding: `systemctl stop trustedge-network`.  
3. Rollback app tree with `scripts/rollback.sh`.  
4. SQLite lives at `/var/lib/trustedge/`; back it up before upgrades (`backup_host_network.sh` also copies it).  
5. Host nft/iptables restore from `/var/backups/trustedge-predeploy/` is **manual** after review.

## Unified pipeline (unchanged on Pi)

Packet capture → features → 50-window baseline → Isolation Forest → Autoencoder → hard rules → EWMA/trust → tier → nft → SQLite → Phase 1 `/p1` dashboard.

No second ML engine. No second firewall engine.
