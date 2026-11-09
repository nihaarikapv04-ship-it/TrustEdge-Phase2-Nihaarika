# TrustEdge Phase A — Software Release

**Status:** Software release for local-first Raspberry Pi operation.  
**Physical IoT gateway commissioning (DHCP/dnsmasq/eth1 NAT) is pending and not claimed here.**

## Goals completed in this release

1. Durable firewall image bake + controlled firewall-only recreation (prior milestone; ML hashes frozen).
2. Remove TrustEdge application cloud telemetry / CDN phone-home from the dashboard UI.
3. Extend local SQLite persistence (WAL, schema v2, enforcement + health tables).
4. Fix Phase 1 API/dashboard integration defects (audit-log filtering, stale flag, status health).
5. Strengthen nftables apply verification (read-back) and enforcement audit records.
6. Document architecture, backup/restore, and remaining physical steps.

## Frozen ML / trust logic

Do **not** modify algorithm bodies in:

| File | Accepted SHA-256 |
|------|------------------|
| `trustedge/detection.py` | `01fa5d2fb926d16445ff970af44bf8ddb84c883e85cd566f8e0a26a25edee720` |
| `trustedge/simulation.py` | `41c82572add8d79e3ea2479891b2c190a1a9f375e81c9e90ed151851525b8fc4` |

Preserved: `phase1-14-v1`, Isolation Forest, autoencoder, densify, diagnostic envelopes, IF freeze, trust scoring, three-window transitions, TRUSTED/CAUTIOUS/QUARANTINE, hard rules.

## Local architecture

```
Raspberry Pi 5
  → TrustEdge backend/API (python -m trustedge)
  → SQLite WAL database on Docker volume lab_lab-db
  → Detection + trust engine (frozen)
  → nftables enforcement (inet trustedge)
  → Phase 1 dashboard (/phase1, /p1/*)
```

No mandatory cloud account. No third-party analytics SDK. Tailscale remains for remote admin only.

## Cloud telemetry removal

| Item | Action |
|------|--------|
| Google Fonts CDN | Removed; system font stack |
| Chart.js jsDelivr CDN | Vendored at `/vendor/chart.umd.min.js` |
| CSP CDN allowlist | Removed from Phase 1 CSP |
| `/p1/cloud/*` | Explicitly returns disabled / empty |
| Lab `wan-sink` `/telemetry` | **Kept** — simulated IoT device traffic sink, not TrustEdge phone-home |

## Database

- Engine: SQLite, `PRAGMA journal_mode=WAL`, `synchronous=FULL`, foreign keys ON.
- Volume: `lab_lab-db` → `/var/lib/trustedge/lab.sqlite` (never delete / never `compose down -v`).
- Schema version: metadata `schema_version=2`.
- New tables: `enforcement`, `system_health`; indexes on events/windows/enforcement.
- Retention: 300 windows/device, 10k windows total, 10k events, 5k enforcement rows.
- Device JSON gains: `mac`, `enrollment_status`, `enrolled_at`, `first_seen_at`, `last_seen_at`, `previous_tier`, `tier_changed_at`.

### Backup / restore (Pi)

```bash
# Consistent online backup (Pi SSH)
CID=$(docker ps --filter name=trustedge-lab-firewall --format '{{.ID}}')
docker exec "$CID" python3 -c 'import sqlite3,os; os.makedirs("/tmp/te_bak",exist_ok=True); s=sqlite3.connect("/var/lib/trustedge/lab.sqlite"); d=sqlite3.connect("/tmp/te_bak/lab.sqlite"); s.backup(d); d.close(); s.close()'
docker cp "$CID:/tmp/te_bak/lab.sqlite" ~/trustedge-backups/lab-$(date -u +%Y%m%dT%H%M%SZ).sqlite

# Restore requires stopping ONLY the firewall container, replacing the volume file,
# then starting firewall again — never compose down -v. Prefer operator-guided restore.
```

## API highlights

| Route | Notes |
|-------|-------|
| `POST /p1/auth/login` | JWT session |
| `POST /p1/auth/refresh` | Refresh JWT |
| `GET /p1/status` | Local health + DB counts; cloud disabled |
| `GET /p1/devices` | Persisted device views (stale, enforcement_pending) |
| `GET /p1/audit-log` | Filtered security/operator actions |
| `GET /p1/enforcement` | Enforcement audit rows |
| `GET /p1/cloud/*` | Disabled stub |
| `GET /phase1` | Dashboard HTML |

## Firewall

- Owned table: `inet trustedge` (atomic delete+recreate per reconcile).
- NAT: `ip trustedge_nat` (lab entrypoint).
- Apply now verifies table presence via `nft -j list table inet trustedge` before advancing `applied_tier`.
- Failures persist `enforcement_failed` events + `enforcement` rows + health snapshot.
- Do not flush nftables; do not disable Tailscale; do not change WAN routing in Phase A.

## Physical commissioning — still pending

Not done in Phase A:

- Physical IoT DHCP / dnsmasq on `eth1`
- Physical NAT/forwarding for `192.168.10.0/24`
- Connecting real IoT devices
- End-to-end physical quarantine validation on copper

See prior commissioning drafts under Pi backups:
`/home/pi/trustedge-backups/durable-image-20261109T120137Z/net/iot-plan/`

## GitHub

- Target repo: `nihaarikapv04-ship-it/TrustEdge-Phase2-Nihaarika`
- Branch: `phase-a-software-release`
- Do not force-push `main`
