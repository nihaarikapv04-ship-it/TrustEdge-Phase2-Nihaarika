# TrustEdge Phase 2 — local Raspberry Pi gateway

TrustEdge learns device behavior, evaluates trust, and controls network access locally. The project includes a dashboard and a no-hardware demonstration. The real Pi setup uses native Python services rather than Docker, with no cloud telemetry, monitoring emails, or cloud model updates.

**Current status:** the software and local demonstration are implemented. Physical Pi operation, Linux packet-path tests, and browser visual checks still need validation. See the [plain language handover](docs/PLAIN_LANGUAGE_HANDOVER.md) or [developer handoff](START_HERE.md) for the full scope.

## Set up the project once

If this folder is already installed and you have used the dashboard before, skip to **Open the dashboard** below.

For a new computer, download or clone this Phase 2 repository and open a terminal in the project folder. Use Python 3.11, matching the reference environment. Python 3.10–3.13 is supported by the project; the commands below assume Python 3.11 is installed.

```sh
python3.11 -m venv .venv
.venv/bin/python -m pip install -e .
```

This creates a separate Python environment and installs the project's dependencies. Do this once per computer. Recreate the environment on the Pi; do not copy the Mac's `.venv` folder to it. Dependency installation needs Internet access or a prepared offline package source; the running dashboard uses bundled local assets.

## Open the dashboard

### On a Mac

Double-click **Dashboard.command** in the project folder. It starts the demonstration, opens your browser, and signs you in automatically. You do not need to create or copy an API token, use `curl`, or run a second terminal.

### From a terminal

Run this from the project folder:

```sh
.venv/bin/python -m trustedge.dashboard
```

This is the same launcher used by `Dashboard.command`. Keep its terminal window running while using the dashboard. Press **Ctrl+C** in that window to stop it.

The launcher creates a short-lived, single-use local sign-in link. Authentication remains enabled. If you reload or disconnect and see the token form, stop and restart the launcher to open a fresh automatically signed-in session. If the browser does not open, the launcher prints a single-use local link you can open within two minutes.

If another application uses port 8080, choose a different port:

```sh
.venv/bin/python -m trustedge.dashboard --port 8081
```

If TrustEdge is already running, stop that instance before launching it again.

## What the demonstration shows

The first launch creates five fictional devices: Studio laptop, Living room camera, Office printer, Hallway thermostat, and Guest device. These are saved example records, not discovered devices, virtual machines, or Docker containers. Example traffic descriptions pass through the real Phase 1 learning and trust code; no example packets are sent over your network.

The launcher saves its simulation state in `dashboard-local.sqlite` and reuses it on later launches. Earlier actions and quarantine decisions remain saved. Three examples begin trained and trusted, one is still learning, and the Guest device has repeated simulated scan windows to demonstrate quarantine. Your saved states may differ after using the controls or running an earlier version.

Use the dashboard to inspect devices, view trust and traffic history, explore the animated topology, and try the clearly labeled simulation buttons. You can also enroll devices, edit expected destinations, release quarantine with a reason, restart learning, and remove devices through the dashboard.

- One scan lowers trust and records a detection; it does not force immediate quarantine. Repeated suspicious windows validate one-tier downgrades.
- **Release to cautious** is the explicit way to give a reviewed quarantined device limited access again.
- **Rebaseline** starts learning again and does not release quarantine.
- “Confirmed policy” in simulation means the simulation accepted the decision; no real firewall was changed.

To start a separate demonstration without deleting the existing one, choose an unused database filename:

```sh
.venv/bin/python -m trustedge.dashboard --database another-demo.sqlite
```

Simulation never starts live capture or changes the host firewall. Simulation and live databases cannot be used interchangeably. The simple launcher always starts simulation; attaching a Pi or a device does not turn it into live operation.

For all seven dashboard pages, access details, and troubleshooting, see the [dashboard guide](docs/DASHBOARD.md).

## Docker Compose lab (local only)

For Phase 1-style multi-container evaluation on this machine, see [`lab/README.md`](lab/README.md). The lab runs the Phase 2 backend with Phase 1 LAN/WAN device containers. It does not replace Pi deployment and does not enable cloud telemetry.

## Raspberry Pi deployment

Deployment is prepared for a Pi 4 with built-in Ethernet WAN and a USB Ethernet LAN. It uses native Python/systemd, local dnsmasq and nftables, with no Docker or cloud services. See [the deployment guide](docs/PI_DEPLOYMENT.md) for wiring, configuration, artifact installation and hardware acceptance tests.

Generate deployment files without changing your host network:

```sh
.venv/bin/python -m trustedge.hardware render \
  --config deploy/pi.example.json --output build/my-pi
```

Once the reviewed artifacts are installed on the Pi, the application runs with `python -m trustedge --config /etc/trustedge/gateway.json`. The service loads deny rules and NAT before enabling forwarding; its preflight validates the local setup without Internet probes. Actual hardware commissioning remains pending.

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
| `dashboard.py` | One-command demonstration launcher, dashboard projections and local host health |
| `static/` | Responsive dashboard, local SVG charts, no external assets |
| `simulation.py` | Offline fixtures, available only in simulation mode |

The default detector now integrates Phase 1's **14-feature extraction, StandardScaler, 100-tree Isolation Forest, calibrated score normalization, and sklearn MLP autoencoder (14→6→3→6→14)**. It uses 50 eligible baseline windows, at least five packets per window, Phase 1 hard rules, and local rolling refits. No trained `.pkl` artifacts were present in the reference repository: devices train locally unless you explicitly import trusted Phase 1 artifacts. See [ML compatibility and artifact import](docs/PHASE1_ML.md) for exact behavior and boundaries. Live capture uses full-frame lengths, timestamps, source/destination ports and TCP flags matching the original feature contract; no payloads are retained. Detection evaluates 60-second windows and requires validation with real device traffic.

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

Protected API requests require `Authorization: Bearer <token>`; binding is fixed to `127.0.0.1`. The browser launcher handles sign-in automatically for simulation. Public assets contain no credentials; its optional pairing endpoint accepts only a same-origin, unexpired, single-use code. Use an SSH tunnel for remote administration. JSON bodies are limited to 8 KiB.

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

## Optional developer startup

These commands are an alternative for developers testing the API directly. **They are not required for the dashboard launcher above.** They use manual token authentication and start an empty registry when the chosen simulation database is new; an existing simulation database is reused. They do not populate the automatically signed-in demonstration.

<details>
<summary>Show manual API startup commands</summary>

Run from the project folder after the one-time installation:

```sh
export TRUSTEDGE_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
.venv/bin/python -m trustedge --mode simulation --database simulation.sqlite
```

This path does not open a browser or sign in automatically. API clients must send the generated token in the authorization header. To use the normal dashboard experience, stop this process and use `.venv/bin/python -m trustedge.dashboard` instead. The production Pi service also requires its own configured administrative key; automatic demo pairing is not enabled for live gateways.

</details>

## Validation

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q trustedge tests
# Linux only, root, nft + util-linux required; isolated namespace, no host rule edits:
sudo env TRUSTEDGE_NFT_TESTS=1 .venv/bin/python -m unittest discover -s tests -p test_nft_linux.py -v
```

Tests include frozen Phase 1 parity checks for feature extraction, IF/AE training, calibration, scoring, hard rules and trust EWMA, adaptive signature milestones, hardware configuration/rendering/preflight, plus artifact import, model restart recovery, rolling refits and failed-training rollback. Gateway tests cover enforcement exit errors/timeouts, failed enrollment/downgrade/deletion/rebaseline, restart reconciliation, persistent trust/baseline/streaks, stale buffered windows, API authentication/failure responses, destination/rule ordering, and mode isolation. The opt-in Linux tests cover actual nft syntax, replacement/rollback and routed TCP/UDP packet paths in disposable network namespaces. They remain unexecuted on this development host. Physical Pi forwarding, DHCP/DNS and packet-level policy behavior must be validated on the deployment network; they cannot be exercised on this macOS development host.

nft table lifecycle and hook semantics: [official nftables manual](https://netfilter.org/projects/nftables/manpage.html).

## Phase 1 reference

The [Phase 1 repository](https://github.com/nehadevarasetty/TrustEdge-firewall) was inspected read-only at commit `ae8ecc7f64e1b0838dd13f7281ee53bdca143c75`. It remains unmodified; this Phase 2 project is maintained separately. The monolithic runtime is not imported, and its cloud integration is excluded.
