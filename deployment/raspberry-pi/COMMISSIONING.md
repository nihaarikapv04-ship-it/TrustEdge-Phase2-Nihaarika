# Staged Raspberry Pi commissioning (manual)

**Known-good local RC:** preserve with `scripts/preserve_local_rc.sh` before any Pi work.  
**This document does not run on the Pi by itself.** Every stage that touches hardware is **manual**.

Do **not** push to GitHub. Do **not** let automation change eth0/eth1.

---

## Before you start (on Mac — local)

| Step | Who | Command / action |
| --- | --- | --- |
| A. Tag + tarball RC | **You** | `./deployment/raspberry-pi/scripts/preserve_local_rc.sh rc-local-pre-pi` |
| B. Copy repo to Pi | **You** | Use the verified rsync below (do **not** omit excludes) |

```sh
# From repo root on the Mac — verified dry-run: secrets / .git / RC tarballs excluded
rsync -a \
  --exclude '.venv' \
  --exclude '.git' \
  --exclude 'lab/.env' \
  --exclude 'lab/.env.token' \
  --exclude 'lab/.admin.password' \
  --exclude 'lab/.operator.password' \
  --exclude 'lab/.viewer.password' \
  --exclude 'deployment/raspberry-pi/rc-snapshots/*.tar.gz' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '.DS_Store' \
  ./ pi@PI_HOST:/opt/trustedge-src/
```
| C. Keep Mac lab untouched | — | Do not `compose down -v`; leave local SQLite/volume as rollback evidence |

---

## Stage 0 — Inspect architecture and Docker (read-only)

**Manual on Pi.**

```sh
uname -m                    # expect aarch64
cat /etc/os-release
command -v docker && docker version || echo 'no docker (OK for native prod)'
sudo /opt/trustedge-src/deployment/raspberry-pi/scripts/host_preflight.sh --prod
```

**Pass criteria:** 64-bit OS; `nft` and `ip` available; eth0/eth1 (or `enx…`) listed; no config changes.

---

## Stage 1 — Inspect eth0 / eth1 without changing them

**Manual on Pi.**

```sh
ip -br link
ip -br addr
ip route
# Identify: WAN = uplink toward router; LAN = USB NIC toward IoT switch/AP
# Do NOT: nmcli modify, ip addr add, or rewrite /etc/netplan yet
```

Record actual names in your private notes. Update `deploy/pi.example.json` copy **on paper/editor only** until Stage 3.

---

## Stage 2 — Back up existing network and firewall

**Manual on Pi (root).**

```sh
sudo /opt/trustedge-src/deployment/raspberry-pi/scripts/backup_host_network.sh
# default output: /var/backups/trustedge-predeploy/<timestamp>/
ls -la /var/backups/trustedge-predeploy/
```

**Pass criteria:** `nft_ruleset.txt`, `ip_snapshot.txt`, and relevant `/etc` copies present.

---

## Stage 3 — Deploy gateway and test **one** device

**Manual on Pi.** Prefer **native production** path (`docs/PI_DEPLOYMENT.md`).

```sh
# 1) Packages
sudo apt-get update
sudo apt-get install -y python3 python3-venv nftables iproute2 util-linux dnsmasq libpcap0.8

# 2) Install tree (keep previous if upgrading)
sudo mkdir -p /opt
sudo cp -a /opt/trustedge /opt/trustedge.prev 2>/dev/null || true
sudo rsync -a --delete --exclude .venv /opt/trustedge-src/ /opt/trustedge/
cd /opt/trustedge
python3 -m venv .venv
.venv/bin/pip install .

# 3) Render hardware artifacts (after editing a private copy of pi.example.json)
.venv/bin/python -m trustedge.hardware render \
  --config /path/to/my-pi.json --output /opt/trustedge/build/my-pi
# Review build/my-pi/* then copy into /etc/trustedge, NM, dnsmasq, systemd
# as described in docs/PI_DEPLOYMENT.md — do not skip review.

# 4) Env
sudo cp deployment/raspberry-pi/.env.example /etc/trustedge.env
sudo chmod 600 /etc/trustedge.env
sudoedit /etc/trustedge.env   # real tokens; confirm LAN/WAN IF names

# 5) Enable services
sudo systemctl daemon-reload
sudo systemctl enable --now nftables
sudo systemctl enable --now trustedge-network trustedge

# 6) One client only on IoT LAN (wired laptop recommended)
# Enroll its DHCP IP via SSH tunnel API (CAUTIOUS + explicit destinations)
```

**Pass criteria:** `systemctl is-active trustedge`; `scripts/validate.sh` OK; one enrolled device.

---

## Stage 4 — Packet capture, forwarding counters, HTTP/DNS

**Manual on Pi.**

```sh
# Capture / API
sudo journalctl -u trustedge -n 50 --no-pager
curl -s -H "Authorization: Bearer $TRUSTEDGE_API_TOKEN" http://127.0.0.1:8080/status | python3 -m json.tool | head

# nft
sudo nft list table inet trustedge
sudo nft list table ip trustedge_nat

# From the single LAN client:
#   - DNS to Pi resolver succeeds
#   - HTTP to an enrolled destination succeeds if CAUTIOUS/TRUSTED
#   - SYN to non-enrolled destination fails
# Optional: temporary counter rules (same technique as local lab proof), then remove
```

**Pass criteria:** windows appear for the device IP; forward/NAT counters move; DNS+HTTP match tier.

---

## Stage 5 — Add remaining four devices

**Manual.** Enroll one at a time. After each: confirm DHCP, DNS, tier, nft rules, dashboard `/p1`.

Do not connect clients to the upstream router Wi-Fi (bypass).

---

## Stage 6 — Trust, quarantine, dashboard

**Manual exercises (one controlled device):**

1. Generate ordinary traffic → trust stays high / tier TRUSTED or CAUTIOUS as expected.  
2. Trigger a **lab-safe** anomaly only if you accept quarantine (or use a disposable test client).  
3. Confirm QUARANTINE: HTTP blocked, DNS allowed.  
4. Confirm dashboard `/status` and `/p1` match `nft` and SQLite.  
5. Remember: Phase 2 **does not** auto-release quarantine — use audited release.

---

## Stage 7 — Reboot persistence

**Manual on Pi.**

```sh
sudo reboot
# after reboot:
ip -br addr
sudo systemctl is-active trustedge-network trustedge nftables dnsmasq
sudo nft list table inet trustedge | head
ls -la /var/lib/trustedge/
sudo /opt/trustedge/deployment/raspberry-pi/scripts/validate.sh
# Re-check one client: DHCP renew, DNS, HTTP, dashboard tiers unchanged
```

**Pass criteria:** forwarding restored; DB/models/tiers intact; policy denies unknown traffic before enroll.

---

## Lab-on-Pi (optional — not production)

Only if you deliberately run Compose on the Pi:

```sh
sudo /opt/trustedge-src/deployment/raspberry-pi/scripts/host_preflight.sh --lab
# Review DOCKER-USER warnings, then optionally:
sudo /opt/trustedge-src/deployment/raspberry-pi/scripts/block_docker_bridge_bypass.sh
cd /opt/trustedge/lab
# fill .env from deployment/raspberry-pi/.env.example + lab token
docker compose -f docker-compose.yml -f ../deployment/raspberry-pi/docker-compose.lab-on-pi.yml up -d --build
./scripts/prove_firewall_path.sh
./scripts/comm_smoke_test.sh
```

---

## Rollback if deployment fails

| Asset | Location |
| --- | --- |
| Local RC tarball | `deployment/raspberry-pi/rc-snapshots/rc-local-*.tar.gz` (on Mac) |
| Local git tag | `git tag -l 'rc-local-*'` (not pushed) |
| Previous Pi tree | `/opt/trustedge.prev` → `scripts/rollback.sh /opt/trustedge.prev` |
| Host backup | `/var/backups/trustedge-predeploy/<stamp>/` |

```sh
# App-only rollback on Pi (keeps last nft until you stop trustedge-network):
sudo /opt/trustedge/deployment/raspberry-pi/scripts/rollback.sh /opt/trustedge.prev

# Stop forwarding entirely:
sudo systemctl stop trustedge trustedge-network
```

Restore host nft/iptables from the Stage 2 backup **manually** after review — never auto-flush unrelated rules.

---

## What this agent will not do

- SSH into your Pi or change eth0/eth1  
- Push git tags or branches to GitHub  
- Apply DOCKER-USER or nft rules remotely  
