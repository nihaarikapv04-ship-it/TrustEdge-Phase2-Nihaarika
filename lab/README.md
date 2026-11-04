# TrustEdge Docker Compose lab

Local evaluation topology matching Phase 1 LAN/WAN addressing, running the **Phase 2** gateway backend.

| Layer | Source |
| --- | --- |
| Device + WAN containers | Phase 1 Compose layout (`172.20.0.0/24` / `172.21.0.0/24`) |
| Firewall / detection / policy / API | Phase 2 `trustedge` package |
| Pi production | Native systemd/nft — see `deployment/raspberry-pi/` and `docs/PI_DEPLOYMENT.md` |

Intentionally omitted from Phase 1 Compose: MailHog/SMTP, Supabase, and firewall→cloud telemetry uploads. `wan-sink` keeps destination `172.21.0.11` for camera/thermostat/printer traffic generators without any TrustEdge upload worker.

## Networking contract

- Two bridges: devices on **lan** only; webserver/wan-sink/dns on **wan** only; **firewall on both**.
- Devices **must** default-route via `172.20.0.2` (firewall), not Docker’s `172.20.0.1` host bridge.  
  `ensure_gateway.sh` enforces this (watchdog). If devices keep `*.1`, Linux hosts can forward LAN↔WAN **around** TrustEdge and capture sees nothing.
- Never use `localhost` for peers.
- Firewall publishes API on `0.0.0.0:8080` only when `TRUSTEDGE_LAB_BIND=1`.
- Devices wait for firewall **healthcheck** before starting.

Prove the path (tcpdump + counters on the firewall LAN iface):

```sh
./scripts/prove_firewall_path.sh
```

## Prerequisites

- Docker Desktop (or Docker Engine + Compose)
- A lab API token of at least 24 characters
- Free Docker address space for `172.20.0.0/24` and `172.21.0.0/24`

## Start

From this `lab/` directory:

```sh
export TRUSTEDGE_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
export TRUSTEDGE_ADMIN_PASSWORD='lab-admin-password'
echo "$TRUSTEDGE_API_TOKEN" > .env.token   # local only; gitignored
docker compose up --build -d
./scripts/enroll_lab_devices.sh
./scripts/comm_smoke_test.sh
```

Optional live three-window ML downgrade (real capture):

```sh
python3 -u ./scripts/live_three_window_validate.py
```

Dashboard / API:

- http://127.0.0.1:8080/
- http://127.0.0.1:5001/ (Phase 1 port alias)

## Stop

```sh
docker compose down
# optional: also drop persisted lab SQLite
docker compose down -v
```

## Behaviour notes

- Unknown devices remain denied until enrolled; enrollment starts **CAUTIOUS**.
- Expected destinations for lab devices are `172.21.0.10` (webserver) and `172.21.0.11` (wan-sink).
- Detection window **count** is Phase 1’s 50-window baseline. Lab may set `TRUSTEDGE_WINDOW_SECONDS=5` for wall-clock only; production default remains 60s.
- Hard-rule hits force trust to 0.1 and quarantine immediately.
- This lab exercises container routing and Phase 2 live capture/policy. It is not a substitute for Pi commissioning.
