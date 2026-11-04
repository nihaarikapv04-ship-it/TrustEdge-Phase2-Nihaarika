# Local Phase 1 behavioural parity report

**Date:** 2026-11-04 (Docker communication checkpoint + authorised GitHub push)  
**Branch:** `phase2-integration`  
**Local RC tag:** `rc-local-pre-pi` (annotated; **tags not pushed**)  
**RC archive:** `deployment/raspberry-pi/rc-snapshots/rc-local-pre-pi.tar.gz` (local only)  
**Physical Raspberry Pi:** not touched  

**Baseline requirement:** Phase 1 parity **`BASELINE_WINDOWS = 50`** (confirmed in `trustedge/detection.py`; ARM64 image imports `50`).

### Checkpoint test results (this push)

| Suite | Label | Result |
| --- | --- | --- |
| `unittest discover -s tests` | Unit / simulation | **74 OK** (2 skipped) |
| `lab/scripts/comm_smoke_test.sh` | macOS Docker integration | **PASS=28 FAIL=0** |
| `lab/scripts/prove_firewall_path.sh` | macOS Docker live packet path | **PASS=5/5** devices on fw LAN |
| `TRUSTEDGE_NFT_TESTS=1` nft suite | Linux integration (privileged aarch64 container) | **2/2 OK** |
| `trustedge-gateway:arm64-local` | ARM64 build host | Arch=arm64; `BASELINE_WINDOWS=50` import OK |

Healthchecks: wan-sink `/ping` healthy; webserver `wget` healthy.

---

## LOCAL READY decision

### **LOCAL READY** (macOS Docker lab + Linux/aarch64 container tests)

Local behavioural parity for the dual-bridge lab, live ML three-window path, hard-rule quarantine, nft enforcement isolation, gateway datapath, and ARM64 package build is satisfied. Residual quarantines on laptop/phone/printer are **intentional evidence**, not blockers.

### Remaining blockers (not local-lab)

| Blocker | Severity | Notes |
| --- | --- | --- |
| Physical Raspberry Pi install / cabling / reboot persistence | **Blocks Pi production** | Package prepared only; no hardware run |
| Host `DOCKER-USER` / UFW bridge-bypass on real Pi Engine | Pi lab-only | Script prepared: `deployment/raspberry-pi/scripts/block_docker_bridge_bypass.sh` |
| Physical commissioning not yet run | Blocks Pi | Follow `deployment/raspberry-pi/COMMISSIONING.md` |

---

## Phase 1 source files inspected

| Area | Phase 1 path |
| --- | --- |
| Config / IF / AE / EWMA / streaks / hard rules | `~/cursor/trustedge-phase1-reference/containers/firewall/pipeline.py` |
| Signatures | `containers/firewall/signature_collector.py` |
| DNS/HTTP enforcement (iptables `apply_policy`) | `pipeline.py` |

## Phase 2 files touched for this pass

- `lab/docker-compose.yml` — explicit dual-bridge nets, healthchecks, DNS aliases, device env IPs, firewall readiness
- `lab/containers/*/traffic_gen.sh` — env-based gateway/sink IPs; pause flag for validation
- `lab/scripts/live_three_window_validate.py` — live Docker three-window + hard-rule harness
- `lab/scripts/comm_smoke_test.sh` — container communication integration test
- `lab/scripts/prove_firewall_path.sh` / path matrix artifacts
- `deployment/raspberry-pi/**` — Pi deployment package
- Reports: this file + `deployment/raspberry-pi/DEPLOYMENT_REPORT.md`

---

## 1. Docker traffic path (five devices)

**Test level:** macOS Docker integration  
**Artifacts:** `lab/results/firewall_path_proof.txt`, `lab/results/final_path_matrix.json`, `lab/results/nft_forward_counter_proof.txt`

| Device | IP | Network | Default GW | Route table (summary) |
| --- | --- | --- | --- | --- |
| Studio laptop | 172.20.0.10 | `lab_lan` only | **172.20.0.2** | `default via 172.20.0.2 dev eth0`; `172.20.0.0/24 dev eth0` |
| Living room camera | 172.20.0.11 | `lab_lan` | **172.20.0.2** | same pattern |
| Hallway thermostat | 172.20.0.12 | `lab_lan` | **172.20.0.2** | same pattern |
| Guest phone | 172.20.0.13 | `lab_lan` | **172.20.0.2** | same pattern |
| Office printer | 172.20.0.14 | `lab_lan` | **172.20.0.2** | same pattern |

Generated real HTTP (TCP/80 to `172.21.0.10` / `.11`) and DNS (UDP/53 to `172.21.0.12`).

| Proof | Result |
| --- | --- |
| Packets on firewall LAN `eth0` (tcpdump/Scapy) | **PASS** all five (pcap lines > 0; `rx_packets` delta > 0) |
| Gateway pipeline windows | New windows observed per device during path runs |
| nft forward counters (temporary verify rules) | laptop **0→6** pkts; thermostat **0→38** pkts then rules removed |

Quarantined devices still arrive on the LAN iface (SYN visible) and hit forward-path counters before the per-IP `drop` rule.

---

## 2. Enforcement isolation

**Quarantine subject:** Studio laptop `172.20.0.10` (also phone/printer still Q).  
**Permitted control:** Hallway thermostat `172.20.0.12` TRUSTED.

| Check | Result |
| --- | --- |
| Laptop WAN HTTP `http://172.21.0.10/` | **blocked** (`http_code=000`) |
| Thermostat WAN HTTP | **allowed** (`200`) |
| Laptop DNS UDP/53 → `172.21.0.12` | **allowed** (response received) |
| Thermostat DNS | **allowed** |
| Phone HTTP | **blocked** (QUARANTINE) |
| nft laptop | DNS accept + `ip saddr 172.20.0.10 drop` |
| nft thermostat | `ip saddr 172.20.0.12 accept` + established |

DNS rules verified separately from HTTP (QUARANTINE keeps unlimited UDP/53; CAUTIOUS uses `limit rate 10/minute`).

---

## 3. Communication matrix (expanded; smoke 28/28)

**Smoke:** `./lab/scripts/comm_smoke_test.sh` → **PASS=28 FAIL=0** (`lab/results/comm_smoke_test.txt`).  
**Path proof:** `prove_firewall_path.sh` → **5/5** (`lab/results/firewall_path_proof.txt`).  
**Expanded:** `lab/results/communication_matrix.json` (+ `.md`).

Distinction:

- **Ordinary container connectivity** — same Docker network L2 (e.g. firewall→webserver on `lab_wan`); does **not** prove TrustEdge datapath.
- **Via firewall datapath** — device on `lab_lan`, default GW `172.20.0.2`, WAN peer on `lab_wan`; must appear on fw `eth0` and nft forward.

| Path | Src → Dst | Proto/port | Via FW | Result | Evidence |
| --- | --- | --- | --- | --- | --- |
| FW → webserver | 172.21.0.2 → .10:80 | TCP/HTTP | ordinary | PASS 200 | curl from firewall |
| FW → wan-sink | → .11:80 `/ping` | TCP/HTTP | ordinary | PASS 200 | curl |
| Compose DNS aliases | firewall getent | Docker DNS | ordinary | PASS | webserver/wan-sink/dns/laptop |
| laptop → WAN HTTP | .10 → .10/.11:80 | TCP/HTTP | **YES** | PASS_PATH / HTTP blocked | pcap + nft Q drop |
| laptop → DNS | .10 → .12:53 | UDP/DNS | **YES** | PASS | DNS resp |
| camera → WAN HTTP | .11 → :80 | TCP/HTTP | **YES** | PASS_PATH | pcap; tier-dependent HTTP |
| camera → DNS | .11 → .12:53 | UDP/DNS | **YES** | PASS | DNS resp |
| thermo → WAN HTTP | .12 → :80 | TCP/HTTP | **YES** | PASS_PATH + HTTP 200 | pcap + nft accept |
| thermo → DNS | .12 → .12:53 | UDP/DNS | **YES** | PASS | DNS resp |
| phone → WAN HTTP | .13 → :80 | TCP/HTTP | **YES** | PASS_PATH / HTTP blocked | pcap + Q drop |
| phone → DNS | .13 → .12:53 | UDP/DNS | **YES** | PASS | DNS resp |
| printer → WAN HTTP | .14 → :80 | TCP/HTTP | **YES** | PASS_PATH / HTTP blocked | pcap + Q drop |
| printer → DNS | .14 → .12:53 | UDP/DNS | **YES** | PASS | DNS resp |
| laptop localhost ≠ peer | 127.0.0.1:80 | TCP/HTTP | n/a | FAIL_AS_DESIGNED | negative test |
| Isolation Q vs TRUSTED | laptop vs thermo | HTTP+DNS | **YES** | PASS | see §2 |

---

## 4. Clean recovery vs Phase 1 rule

### Exact Phase 1 rule (`pipeline.py`)

- `UPGRADE_WINDOWS = 10`
- When `tier_rank(target) > tier_rank(current)`, `normal_streak` increments; at **≥ 10** the tier is raised to `target` (Phase 1 allowed this **including from QUARANTINE** when trust recovered).
- Manual lift: `lift_quarantine` / dashboard release also exists.

### Phase 2 intentional correction (`trustedge/trust.py` + `docs/POLICY_CORRECTIONS.md`)

- `UPGRADE_WINDOWS = 10` retained for **CAUTIOUS → TRUSTED**.
- **QUARANTINE never auto-recovers via clean windows**; operator `POST .../release` only.
- Reason: restricted/quarantined traffic must not “look healthy” and self-release.

### Why the phone did not auto-release after the anomaly test

After hard `PORT_SCAN` (window artifact `label=hard`, trust **0.1**), post-clean windows were classified `reason=quarantined` / insufficient packets. Under Phase 2, clean windows **do not** increment a quarantine escape path. Phone remained `desired_tier=QUARANTINE` — **expected**, not a bug. Behaviour was **not** weakened to restore Phase 1 auto-lift.

### Validated recovery that *is* in scope

| Path | Requirement | Evidence |
| --- | --- | --- |
| CAUTIOUS → TRUSTED | ≥ **10** genuine clean ML windows (`score < 0.50`) | Camera operator-released (`events` id 18055, reason documents UPGRADE_WINDOWS=10); thermostat now **TRUSTED** with `normal_streak` well above 10 under live traffic |
| QUARANTINE auto-release | Must **not** occur | Phone stayed Q after post_clean windows (`live_three_window_latest.json`) |

---

## 5. Device state audit (no silent releases)

Snapshot at final verification (`GET /status` + SQLite `devices.state` + `nft list chain inet trustedge forward`):

| Device | Trust | desired / applied | Detection / cause | nft enforcement | Dashboard agree? | Release? |
| --- | --- | --- | --- | --- | --- | --- |
| **Laptop** `.10` | **0.2835** | QUARANTINE / QUARANTINE | **ML EWMA quarantine** (trust `< 0.4`, not hard-lock). Live trust ≠ `0.1`. Offline hard-rule feature probes earlier in session scored `PORT_SCAN` on synthetic vectors; retained SQLite windows aged out (300-cap) so the scored Q transition is no longer in `windows`. | DNS accept + drop | Yes | **No** — leave as ML-Q evidence |
| **Camera** `.11` | ~0.95–0.97 (varies) | CAUTIOUS / CAUTIOUS (was TRUSTED after release; intermittent ML scores can hold/return CAUTIOUS) | Operator **release** id 18055 for recovery validation; live ML windows | CAUTIOUS: DNS `10/minute` + rate-limited HTTP(S) to enrolled sinks | Yes | Already released **with documented reason** |
| **Thermostat** `.12` | ~0.96–1.0 | TRUSTED / TRUSTED | Healthy live ML | full accept + established | Yes | n/a |
| **Phone** `.13` | **0.1** | QUARANTINE / QUARANTINE | **Hard rule `PORT_SCAN`** — event `9642` (2026-11-04 09:26:48), score 1.0; also `live_three_window_latest.json` hard window (671 pkts) | DNS accept + drop | Yes | **No** — proves Phase 2 no auto-release |
| **Printer** `.14` | **0.1** | QUARANTINE / QUARANTINE | **Hard rules** `VOLUME_ANOMALY` (events 8616, 9132) and `PORT_SCAN` (8842, 8851, 9142) | DNS accept + drop | Yes | **No** — hard-Q evidence |

`insufficient_packets` / `quarantined` on recent windows for Q devices are **post-enforcement** classifications (detection short-circuits), not the original cause.

---

## 6. ARM64 package (summary)

See `deployment/raspberry-pi/DEPLOYMENT_REPORT.md`.

| Check | Result | Where tested |
| --- | --- | --- |
| Compose overlay + lab base `config` | PASS | local aarch64 Docker |
| Image `trustedge-gateway:arm64-local` Arch=arm64 | PASS | local build host |
| `BASELINE_WINDOWS=50`, sklearn, scapy import | PASS | `docker run` arm64 image |
| `.env.example`, start/stop/validate/rollback scripts | Present + executable | package review |
| Linux nft unittest 2/2 | PASS | privileged Linux aarch64 container |
| Physical Pi boot / eth cabling | **Not done** | requires hardware |

---

## 7. Cleanup

Reviewed per `docs/CLEANUP_REPORT.md`. **No deletes** of working source, configs, baselines, models, DBs, or deployment scripts in this final pass. Only noted disposable `__pycache__` / `.pyc` (safe to ignore; not bulk-removed).

---

## Prior results still valid

### Five-device baseline + IF + AE

All five devices reached **50** baseline windows with IF+AE (macOS Docker integration).

### Live Docker three-window ordinary ML downgrade (**PASS**)

**Device:** Guest phone `172.20.0.13`. **Artifact:** `lab/results/live_three_window_latest.json`

| Window | IF / combined | Trust | Tier |
| --- | --- | --- | --- |
| 1 | 0.8395 | 0.832 | TRUSTED |
| 2 | 0.908 | 0.684 | TRUSTED |
| 3 | 0.908 | 0.5656 | **CAUTIOUS** |
| hard | PORT_SCAN 1.0 | **0.1** | **QUARANTINE** |

### Linux nftables kernel tests (**PASS**)

`TRUSTEDGE_NFT_TESTS=1` → 2/2 OK on Linux/aarch64 (`lab/results/nft_linux_test.txt`).

### Unified pipeline

`Scapy capture → features → baseline(50) → IF → AE → hard rules → EWMA/trust → tier → nftables → SQLite → /p1 → dashboard`
