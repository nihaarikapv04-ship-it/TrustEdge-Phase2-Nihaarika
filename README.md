# TrustEdge Phase 2 — local Pi gateway base

Start with [the developer handoff](START_HERE.md) and [Phase 2 migration plan](docs/PHASE2_PLAN.md). Hardware is not required for development. A [plain language project and Pi guide](docs/PLAIN_LANGUAGE_HANDOVER.md) explains the current implementation and handover. The bundled [local dashboard](docs/DASHBOARD.md) includes a ready-to-run explicit simulation demo.

A local Python gateway foundation for a **routed IPv4 Raspberry Pi IoT LAN**. SQLite, capture, detection, trust evaluation and firewall control run on the Pi. There are no telemetry uploads, SMTP alerts, remote models, cloud credentials, CDN assets or runtime Internet dependencies. Python 3.10–3.13 (3.11 recommended), with scikit-learn 1.6.1, NumPy, joblib and Scapy installed locally.

Reference inspected read-only: [TrustEdge-firewall](https://github.com/nehadevarasetty/TrustEdge-firewall), commit `ae8ecc7f64e1b0838dd13f7281ee53bdca143c75`. This is a modular port built in a previously empty workspace; the upstream repository is unmodified and nothing was pushed. The monolithic runtime is not imported, and cloud integration is excluded.

## Responsibilities

| Module | Responsibility |
| --- | --- |
| `registry.py` | Validated, explicit device enrollment and enrollment identity |
| `collection.py` | Live Scapy metadata collection, bounded buffers, capture health |
| `features.py` | Pure window feature extraction |
| `detection.py` | Phase 1 Isolation Forest, calibration, autoencoder and rolling refits |
| `trust.py` | Phase 1 EWMA/noise floor and 3-window downgrade / 10-window recovery |
| `signatures.py` | Persistent Phase 1 adaptive threshold milestones and validation |
| `config.py`, `hardware.py` | Validated Pi configuration, artifact generation and read-only preflight |
| `policy.py` | Atomic, checked nftables enforcement; separate simulation adapter |
| `storage.py` | SQLite WAL, durable device state and bounded audit history |
| `service.py` | Serialized lifecycle operations and enforcement reconciliation |
| `api.py` | Authenticated loopback API and bundled local dashboard |
| `dashboard.py` | Compact dashboard projections and local host health |
| `static/` | Responsive dashboard, local SVG charts, no external assets |
| `simulation.py` | Offline fixtures, available only in simulation mode |

The default detector now integrates Phase 1's **14-feature extraction, StandardScaler, 100-tree Isolation Forest, calibrated score normalization, and sklearn MLP autoencoder (14→6→3→6→14)**. It uses 50 eligible baseline windows, at least five packets per window, Phase 1 hard rules, and local rolling refits. No trained `.pkl` artifacts were present in the reference repository: devices train locally unless you explicitly import trusted Phase 1 artifacts. See [ML compatibility and artifact import](docs/PHASE1_ML.md) for exact behavior and boundaries. Live capture uses full-frame lengths, timestamps, source/destination ports and TCP flags matching the original feature contract; no payloads are retained. Detection evaluates 60-second windows and requires validation with real device traffic.

## Run the local simulation

```sh
python3.11 -m venv .venv
.venv/bin/python -m pip install -e .
export TRUSTEDGE_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
.venv/bin/python -m trustedge --mode simulation --database simulation.sqlite
```

In another shell with the same token:

```sh
curl -H "Authorization: Bearer $TRUSTEDGE_API_TOKEN" http://127.0.0.1:8080/status
curl -H "Authorization: Bearer $TRUSTEDGE_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"ip":"192.168.50.2","name":"camera","destinations":["192.0.2.10"]}' \
  http://127.0.0.1:8080/devices
curl -H "Authorization: Bearer $TRUSTEDGE_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"attack":true}' http://127.0.0.1:8080/devices/192.168.50.2/simulate
```

Simulation never launches capture or nft. A database is permanently marked `live` or `simulation`; using it in the other mode is rejected. Live mode has no simulation endpoint or automatic synthetic fallback.

## Raspberry Pi deployment

Deployment is prepared for a Pi 4 with built-in Ethernet WAN and a USB Ethernet LAN. It uses native Python/systemd, local dnsmasq and nftables, with no Docker or cloud services. See [the deployment guide](docs/PI_DEPLOYMENT.md) for wiring, configuration, artifact installation and hardware acceptance tests.

Generate deployment files without changing your host network:

```sh
.venv/bin/python -m trustedge.hardware render \
  --config deploy/pi.example.json --output build/my-pi
```

Once the reviewed artifacts are installed on the Pi, the application runs with `python -m trustedge --config /etc/trustedge/gateway.json`. The service loads deny rules and NAT before enabling forwarding; its preflight validates the local setup without Internet probes. Actual hardware commissioning remains pending.

## Policy and recovery semantics

- A hard-rule detection scores 1.0 without forcing trust to 0.1. EWMA degradation, three consecutive anomalous windows and one-tier downgrades govern the response; recovery requires ten qualifying normal windows.
- Enrollment begins CAUTIOUS. TRUSTED allows outbound traffic and established replies. CAUTIOUS allows rate-limited HTTP/HTTPS only to explicitly configured destinations, plus configured DNS. QUARANTINE allows only configured DNS; local DHCP remains available. Per-rule limits are packet rates, not bandwidth shaping.
- Rules are ordered explicitly within a single nft batch. No broad established-flow rule bypasses quarantine. Both forward directions are restricted, so an existing connection cannot continue through a tier downgrade. Unknown devices remain denied after deletion.
- Desired policy is committed before enforcement. `applied_tier` changes only after a zero exit status from nft. Rejections, missing binaries and timeouts return HTTP 503 and mark the service unready; intent survives for retry. A timeout is an uncertain outcome, never reported as success.
- SQLite and the kernel cannot share one transaction. A crash after nft applies but before SQLite records success is resolved by reapplying durable intent on restart. `applied_tier` is the last confirmed state, not a fresh kernel inspection. Startup must validate persisted ML state and successfully reconcile before capture/API startup; the runtime reconciles every five seconds to retry failures and repair drift.
- Trust, streaks, adaptive signature thresholds/moments, baseline, rolling windows, detection counters, learning state, desired/applied tier, trained models/scalers/calibration and enrollment generation persist in SQLite. Deletion first writes a tombstone, then removes device state after successful policy replacement. Audit records remain (last 10,000 events); device traffic/baseline state is removed. Late capture cannot re-enroll a device.
- Rebaselining atomically deletes the trained model bundle, clears baseline/rolling/signature data, counters and streaks and increments a generation, rejecting earlier buffered traffic. It preserves trust and quarantine and restricts a formerly trusted device to CAUTIOUS during learning. Empty windows and quarantined traffic cannot train or grant recovery. Quarantine requires an explicit operator release with an audit reason; it never recovers automatically. The dashboard provides that action and rebaselining separately.
- Rule replacement retains the last kernel policy on service exit. A cold boot requires the bootstrap rules above; an application alone cannot guarantee denial before the OS starts it. Back up the SQLite database with SQLite's backup API or while the service is stopped, including WAL state as appropriate.

## API

All API requests require `Authorization: Bearer <token>`; binding is fixed to `127.0.0.1`. Use an SSH tunnel for remote administration. JSON bodies are limited to 8 KiB.

| Method | Path | Action |
| --- | --- | --- |
| GET | `/` | Local dashboard connection screen (public static assets) |
| GET | `/dashboard` | Authenticated dashboard state and recent windows |
| GET | `/devices/<ip>/history` | Retained metadata/trust windows |
| PATCH | `/devices/<ip>` | Update `{name,destinations:[]}` |
| POST | `/devices/<ip>/release` | Explicit CAUTIOUS release with `{reason}` |
| GET | `/status` | Mode, readiness, capture health, device state |
| GET | `/events` | Latest 200 audit records |
| POST | `/devices` | Register `{ip,name,destinations:[],device_type:"custom",rate:5}` |
| DELETE | `/devices/<ip>` | Durable deletion and policy cleanup |
| POST | `/devices/<ip>/rebaseline` | Clear baseline, preserving restrictions |
| POST | `/devices/<ip>/simulate` | Simulation only: one window, `{attack:bool}` |

## Validation

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q trustedge tests
# Linux only, root, nft + util-linux required; isolated namespace, no host rule edits:
sudo env TRUSTEDGE_NFT_TESTS=1 .venv/bin/python -m unittest discover -s tests -p test_nft_linux.py -v
```

Tests include frozen Phase 1 parity checks for feature extraction, IF/AE training, calibration, scoring, hard rules and trust EWMA, adaptive signature milestones, hardware configuration/rendering/preflight, plus artifact import, model restart recovery, rolling refits and failed-training rollback. Gateway tests cover enforcement exit errors/timeouts, failed enrollment/downgrade/deletion/rebaseline, restart reconciliation, persistent trust/baseline/streaks, stale buffered windows, API authentication/failure responses, destination/rule ordering, and mode isolation. The opt-in Linux tests cover actual nft syntax, replacement/rollback and routed TCP/UDP packet paths in disposable network namespaces. They remain unexecuted on this development host. Physical Pi forwarding, DHCP/DNS and packet-level policy behavior must be validated on the deployment network; they cannot be exercised on this macOS development host.

nft table lifecycle and hook semantics: [official nftables manual](https://netfilter.org/projects/nftables/manpage.html).
