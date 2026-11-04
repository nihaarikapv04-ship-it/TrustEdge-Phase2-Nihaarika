# TrustEdge Docker Compose lab

Local evaluation topology matching Phase 1 LAN/WAN addressing, running the **Phase 2** gateway backend.

| Layer | Source |
| --- | --- |
| Device + WAN containers | Phase 1 Compose layout (`172.20.0.0/24` / `172.21.0.0/24`) |
| Firewall / detection / policy / API | Phase 2 `trustedge` package |
| Pi deployment | Unchanged — still native systemd/nft (not this Compose file) |

Intentionally omitted from Phase 1 Compose: MailHog/SMTP, Supabase, and firewall→cloud telemetry uploads. `wan-sink` keeps destination `172.21.0.11` for camera/thermostat/printer traffic generators without any TrustEdge upload worker.

## Prerequisites

- Docker Desktop (or Docker Engine + Compose)
- A lab API token of at least 24 characters
- Free Docker address space for `172.20.0.0/24` and `172.21.0.0/24` (remove any old Phase 1 Compose networks that still hold those subnets)

## Start

From this `lab/` directory:

```sh
export TRUSTEDGE_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
echo "$TRUSTEDGE_API_TOKEN" > .env.token   # local only; gitignored
docker compose up --build -d
./scripts/enroll_lab_devices.sh
```

Dashboard / API (Phase 2 console):

- http://127.0.0.1:8080/
- http://127.0.0.1:5001/ (Phase 1 port alias)

Authenticate with the bearer token from `TRUSTEDGE_API_TOKEN`. Lab bind uses `0.0.0.0` only inside the firewall container and only when `TRUSTEDGE_LAB_BIND=1`.

## Stop

```sh
docker compose down
# optional: also drop persisted lab SQLite
docker compose down -v
```

## Behaviour notes

- Unknown devices remain denied until enrolled; enrollment starts **CAUTIOUS**.
- Expected destinations for lab devices are `172.21.0.10` (webserver) and `172.21.0.11` (wan-sink).
- Detection windows are 60 seconds (Phase 1 contract). Hard-rule hits force trust to 0.1 and quarantine immediately (Phase 1 parity).
- This lab exercises container routing and Phase 2 live capture/policy. It is not a substitute for Pi commissioning.
