# TrustEdge Phase 2 — developer handoff

This repository is a **hardware-independent development base** for a local Raspberry Pi gateway. No Pi is needed to develop or run the standard tests. The reference GitHub repository remains read-only; no changes are pushed to it. Docker and cloud telemetry are not part of the runtime.

For a nontechnical walkthrough, read [the plain language project and Pi guide](docs/PLAIN_LANGUAGE_HANDOVER.md).

Read in this order:

1. [Phase 1 → Phase 2 migration map](docs/PHASE2_PLAN.md): architecture, carried-over behavior, deliberate differences and remaining work.
2. [ML compatibility](docs/PHASE1_ML.md): feature contract, training, import of separately saved Phase 1 weights.
3. [Pi deployment](docs/PI_DEPLOYMENT.md): configuration and deployment files; use when hardware arrives.
4. [Local dashboard](docs/DASHBOARD.md): seven console areas and an explicit simulation demo.
5. [README](README.md): API endpoints, local simulation and test commands.

## Work without hardware

Use Python 3.11 (matching Phase 1's runtime):

```sh
python3.11 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

The ordinary suite uses local fixtures and a temporary loopback API server. Linux-only network tests skip unless explicitly enabled. No cloud account, cloud endpoint, Docker daemon, or model download is required. Initial dependency installation needs a package source or an offline wheelhouse.

For an offline dashboard demonstration, double-click `Dashboard.command` on macOS, or run `.venv/bin/python -m trustedge.dashboard`. It opens and signs in automatically without manual API token setup. Explicit simulation uses the real Phase 1 ML algorithms and a simulation policy adapter; it never changes the host firewall or starts capture. Fifty eligible normal windows train the IF, then ten qualifying recovery windows allow TRUSTED. A simulated scan lowers trust and records a PORT_SCAN detection. Consecutive anomalous windows validate a staged downgrade; one scan does not force quarantine.

Generate inspectable deployment files without changing your computer's network:

```sh
.venv/bin/python -m trustedge.hardware render \
  --config deploy/pi.example.json --output build/my-pi
```

Use a new output directory each time; the generator refuses to overwrite existing artifacts. `build/pi` contains the initial example rendering. Do not install these files on a development laptop. The example assumes Ethernet WAN/LAN and must be edited for the Pi's actual interface names and non-overlapping subnet.

## Current completion boundary

Implemented: modular local backend, Phase 1 IF/AE integration and parity tests, adaptive signature validation, Phase 1 tier streak gates, durable device/model/trust state, checked atomic nft policy, deletion/rebaseline recovery, explicit simulation, authenticated loopback API, validated Pi configuration, deployment rendering, and read-only Linux preflight.

Written but **not executed on this macOS development machine**: isolated Linux packet-path tests for bootstrap denial, WAN NAT, CAUTIOUS/TRUSTED/QUARANTINE, DNS/DHCP, existing TCP connections during downgrade, rejected nft batches, restart recovery and deletion. These tests do not constitute physical Pi validation or a real power-cycle test.

The local dashboard now covers enrollment/inspection, destination editing, explicit audited quarantine release, rebaselining, deletion, trust/traffic history and health. Not yet implemented: automatic hardware discovery, per-user RBAC, flow aggregation beyond Phase 1 packet windows, and performance/accuracy benchmarking on real devices. DHCP reservations are configuration, not cryptographic identity or spoof prevention. Browser acceptance and hardware validation are the next deployment milestones.

Your friend can continue without guessing which components have been migrated by using the acceptance checklist in the Phase 2 plan. Keep ML parity tests passing when changing capture or features.
