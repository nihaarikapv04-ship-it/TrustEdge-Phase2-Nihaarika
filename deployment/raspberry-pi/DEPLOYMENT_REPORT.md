# Raspberry Pi deployment report

**Prepared:** 2026-11-04 (Docker communication checkpoint)  
**Workspace:** `~/cursor/trustedge-phase2-integration`  
**Physical Pi changes:** none  
**Git:** authorised push to `origin phase2-integration` only (no tags, no `main`, no PR)  
**Local RC tag:** `rc-local-pre-pi` (**not** pushed)  
**RC tarball:** `deployment/raspberry-pi/rc-snapshots/rc-local-pre-pi.tar.gz` (local only)  

---

## LOCAL READY decision

### **LOCAL READY** for lab + ARM64 package validation on the developer aarch64 Docker host

### **NOT READY** for physical Raspberry Pi production until hardware commission completes

**Next document:** `COMMISSIONING.md` (staged manual procedure).

| Gate | Status |
| --- | --- |
| Live three-window ML + hard-rule quarantine | PASS (macOS Docker) |
| Linux nftables kernel tests | PASS (Linux aarch64 privileged container) |
| Datapath: device → fw eth0 → Scapy → Gateway → nft | PASS (5/5 + counter proof) |
| Enforcement isolation (Q HTTP block / DNS allow) | PASS |
| Communication matrix (28/28 smoke + path 5/5 + expanded evidence) | PASS |
| Phase 2 quarantine non-auto-release + CAUTIOUS→TRUSTED via 10 windows | PASS (documented) |
| ARM64 gateway image + Compose overlay + scripts | PASS (package review / local build) |
| Physical Pi install, eth0/eth1, reboot nft persistence, SSH dashboard | **Not performed** |

Cross-check detail: `docs/LOCAL_PARITY_REPORT.md`.

---

## Executive status

| Area | Status |
| --- | --- |
| Local live three-window ML downgrade | **PASS** (macOS Docker integration) |
| Hard-rule immediate quarantine | **PASS** (same run) |
| Linux nftables kernel tests | **PASS** (Linux aarch64 privileged container) |
| Lab container communication smoke | **PASS** (28/28 macOS Docker) |
| Path proof all five devices via fw LAN | **PASS** (5/5) |
| Expanded communication matrix | **PASS** (`lab/results/communication_matrix.json`) |
| Firewall path + nft forward counters | **PASS** |
| Unit tests | **PASS** 74 OK (2 skipped) |
| Linux nft kernel tests | **PASS** 2/2 (privileged aarch64 container) |
| ARM64 gateway image build + import | **PASS** on aarch64 Docker host |
| Physical Raspberry Pi install/test | **Not performed** |

---

## Docker communication — root cause and fixes

### Original failure mode (lab on Pi / Linux Engine)

**Primary:** device containers keep Docker’s default gateway **`172.20.0.1`** (host bridge). On Linux Engine the host can forward `lab_lan`↔`lab_wan` **around** the firewall container. WAN HTTP still works; **Scapy on the firewall never sees device packets**.

**Fix:** default route **`172.20.0.2`** via `ensure_gateway.sh` + watchdog; `ip_forward`, `rp_filter=0`, LAN `proxy_arp`; nft forward + NAT; optional host `DOCKER-USER` drops (`scripts/block_docker_bridge_bypass.sh`).

### Final path proof (all five devices)

| Device | IP | Net | GW | LAN capture | nft path |
| --- | --- | --- | --- | --- | --- |
| laptop | 172.20.0.10 | lab_lan | 172.20.0.2 | PASS | Q drop after counter match (6 pkts) |
| camera | 172.20.0.11 | lab_lan | 172.20.0.2 | PASS | CAUTIOUS limited forward |
| thermostat | 172.20.0.12 | lab_lan | 172.20.0.2 | PASS | TRUSTED accept (38 counter pkts) |
| phone | 172.20.0.13 | lab_lan | 172.20.0.2 | PASS | Q drop |
| printer | 172.20.0.14 | lab_lan | 172.20.0.2 | PASS | Q drop |

Artifacts: `lab/results/firewall_path_proof.txt`, `final_path_matrix.json`, `nft_forward_counter_proof.txt`.

### Isolation

- Quarantined laptop/phone HTTP → blocked; DNS UDP/53 → allowed.  
- TRUSTED thermostat HTTP → 200; DNS → allowed.

### Communication matrix

Ordinary (same-bridge) vs firewall-datapath rows documented in `docs/LOCAL_PARITY_REPORT.md` §3 and `lab/results/communication_matrix.{json,md}`.

### Network diagram

```text
[laptop/camera/thermo/phone/printer]
        |  172.20.0.10–14
        v
   firewall 172.20.0.2  <── nft inet trustedge + NAT
        |
        +── webserver 172.21.0.10
        +── wan-sink  172.21.0.11
        +── dns       172.21.0.12
```

---

## Recovery audit (Phase 1 vs Phase 2)

| Rule | Phase 1 reference | Phase 2 | Validation |
| --- | --- | --- | --- |
| Upgrade streak | `UPGRADE_WINDOWS=10` (includes Q→up when trust recovers) | Same **10** for CAUTIOUS→TRUSTED; **Q blocked** from auto-upgrade | Camera release + thermostat TRUSTED live streak |
| Q after hard anomaly | Could self-heal after 10 clean windows | **No auto-release** (`trust.py`) | Phone stayed Q after post_clean — correct |
| Operator release | `lift_quarantine` | `POST /devices/<ip>/release` with reason | Camera release event 18055 documented |

No Phase 2 recovery behaviour was weakened for this verification.

---

## Device state audit (left in place)

| Device | Trust | Tier | Cause | Released? |
| --- | --- | --- | --- | --- |
| laptop | 0.2835 | QUARANTINE | ML EWMA (not hard 0.1) | **No** (evidence) |
| camera | ~0.95 | CAUTIOUS | Documented operator release; live ML | Yes (reason recorded) |
| thermostat | ~1.0 | TRUSTED | Healthy | n/a |
| phone | 0.1 | QUARANTINE | Hard `PORT_SCAN` | **No** (evidence) |
| printer | 0.1 | QUARANTINE | Hard `VOLUME_ANOMALY` / `PORT_SCAN` | **No** (evidence) |

`desired_tier` == `applied_tier` == nft policy for each IP at audit time.

---

## Pre-Pi packaging updates (no ML/trust/policy changes)

| Item | Status |
| --- | --- |
| wan-sink healthcheck → `GET /ping` | Fixed in `lab/docker-compose.yml`; container **healthy** |
| `scripts/host_preflight.sh` | DOCKER-USER, ip_forward, nft, NAT, Docker bridges (read-only) |
| `scripts/backup_host_network.sh` | Pre-deploy host backup |
| `scripts/preserve_local_rc.sh` | Local tag + tarball (no push) |
| `COMMISSIONING.md` | Staged 0–7 procedure |
| `.env.example` / validate / rollback / bridge-bypass `--check` | Completed |

Validated ML, trust, DNS rates, `BASELINE_WINDOWS=50`, and nft policy logic were **not** modified.

## ARM64 package validation

### Conducted on Linux/aarch64 (local Docker host)

| Test | Result |
| --- | --- |
| `uname -m` / image `Architecture=arm64` for `trustedge-gateway:arm64-local` | PASS |
| `docker build` via `Dockerfile.gateway` | PASS (`lab/results/arm64_gateway_build.txt`) |
| Import sklearn + scapy; `BASELINE_WINDOWS=50` from `trustedge.detection` | PASS |
| `docker compose -f lab/docker-compose.yml -f deployment/raspberry-pi/docker-compose.lab-on-pi.yml config` | PASS |
| `.env.example` keys (token, LAN/WAN if, bind, DB path) | Reviewed |
| Scripts `start.sh` / `stop.sh` / `validate.sh` / `rollback.sh` / `comm_smoke_lab.sh` / `block_docker_bridge_bypass.sh` | Present, executable; logic reviewed (not executed on Pi) |
| `TRUSTEDGE_NFT_TESTS=1` unittest 2/2 | PASS |

### Still requires physical Raspberry Pi hardware

- Confirm `TRUSTEDGE_LAN_IF` / `TRUSTEDGE_WAN_IF` cabling (eth1 LAN / eth0 WAN)
- Native `trustedge.service` + `trustedge-network` install from `deploy/`
- Capture under real client load; thermal / memory headroom
- nft + SQLite persistence across Pi reboot
- SSH-tunnel dashboard acceptance from MacBook
- Optional lab-on-Pi Compose under real Linux Engine (bridge bypass script)
- End-to-end `scripts/validate.sh` against live `/etc/trustedge.env`

### Dependencies (ARM64)

| Dependency | Status |
| --- | --- |
| Python 3.11 slim arm64 | OK |
| numpy / scikit-learn / joblib | Import OK in image |
| scapy + libpcap0.8 + nftables + iproute2 | In Dockerfile.gateway |
| coredns (lab DNS) | Multi-arch upstream |

### Deployment / rollback (prepared, not executed on Pi)

- Native: stop `trustedge.service`, swap `/opt/trustedge` tree, restart; nft retained until `trustedge-network` stop (`scripts/rollback.sh`).
- Lab overlay: memory/cpu caps + `platform: linux/arm64` for constrained Pi.

---

## Cleanup

No deletion of working source, baselines, models, databases, or deployment scripts. Prior orphan Docker networks removed earlier (`docs/CLEANUP_REPORT.md`). Final pass: review-only (`__pycache__` noted as disposable).

---

## Test label legend

| Label | Meaning |
| --- | --- |
| Unit test | pytest/unittest without Docker capture |
| macOS Docker integration test | Compose lab on developer Mac |
| Linux integration test | Privileged Linux container / Engine with real nft |
| ARM64 build host test | arm64 image build/run on aarch64 Docker (this session) |
| Physical Raspberry Pi test | Real Pi hardware — **none in this session** |
