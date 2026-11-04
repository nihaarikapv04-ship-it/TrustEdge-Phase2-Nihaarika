# Phase 2 local dashboard

The dashboard is bundled with the Python gateway and served at `http://127.0.0.1:8080/`. No frontend build step, Node runtime on the Pi, cloud hosting, CDN, external fonts or remote chart libraries are needed. HTML/CSS/JavaScript assets are included in the installed Python wheel.

## Phase 1 dashboard (compatibility UI)

The original Phase 1 HTML dashboard is served at `http://127.0.0.1:8080/phase1` with a compatibility API under `/p1/*`. Sign in with any username and the gateway bearer token as the password. The Phase 2 local console remains at `/`. Cloud telemetry, WebSocket push, and per-user RBAC are stubbed or omitted; core device/status/history/topology/lift/rebaseline/attack-in-simulation paths are mapped to the Phase 2 gateway.

## Simplest launch — no token copying

On this Mac, double-click **Dashboard.command** in the workspace. Or run:

```sh
.venv/bin/python -m trustedge.dashboard
```

The launcher opens your browser, signs in automatically, and seeds the five-device simulation on first use. Keep its terminal window open; press Ctrl+C to stop. Restarting reuses `dashboard-local.sqlite` and creates fresh session credentials automatically. Use `--port 8081` if 8080 is already occupied.

Authentication is still enforced. The launcher creates an in-memory API token and a random single-use pairing code that expires after two minutes. The code travels only in the local browser URL fragment, is removed immediately, and is exchanged through a same-origin loopback-only POST. The API token never enters a URL or browser storage. Pairing is disabled on ordinary API startup and cannot be enabled for live gateways. Reloading/disconnecting requires restarting the launcher for a new automatic sign-in link, or using the regular token form.

The launcher is explicit **simulation**: no Pi, packet capture, cloud service or actual firewall is used. It never opens an existing live database. The project virtual environment must already be installed as described in START_HERE.md.

## Explore it without hardware

Install the project into the Python 3.11 virtual environment as described in README, then:

```sh
export TRUSTEDGE_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
.venv/bin/python -m trustedge.demo --database dashboard-demo.sqlite
```

Open `http://127.0.0.1:8080/` and paste that token into the connection form. The demonstration creates a **new simulation database** and uses actual Phase 1 training/scoring and the simulation policy adapter to seed five example devices. It refuses existing database paths and never opens capture or modifies the firewall. Its device names and traffic windows are explicit fixtures, not discoveries or live telemetry. Three devices are trained/trusted, one is learning, and one has three consecutive simulated scan windows and a validated quarantine. Use a different database filename for a fresh demo.

To reopen that simulation database after stopping the demo:

```sh
.venv/bin/python -m trustedge --mode simulation --database dashboard-demo.sqlite
```

You can also start a new empty simulation database with that command and enroll devices through the dashboard. Normal-window and simulated-scan controls appear only in simulation mode and generate one fixture window per click. A simulated hard-rule scan forces trust to 0.1 and quarantines immediately (Phase 1 parity). Non-hard ML anomalies still need three consecutive windows per one-tier downgrade. Existing saved quarantine states are preserved; use explicit release to retry a device. The model requires 50 eligible baseline windows; normal recovery requires ten qualifying detection windows.

For real Pi operation, use the reviewed hardware configuration and service from [the deployment guide](PI_DEPLOYMENT.md). Use an SSH tunnel for a remote browser instead of exposing the API:

```sh
ssh -L 8080:127.0.0.1:8080 pi@YOUR_PI_ADDRESS
```

Then open `http://127.0.0.1:8080/` on your workstation. Use the token configured for that gateway. No token appears in a URL or static asset.

## Console areas

| Area | Real data and controls |
| --- | --- |
| Overview | Pipeline readiness, device counts, average persisted trust, confirmed quarantine, pending policies, observed packet windows, distribution, recent signals |
| Devices | Search and tier filters; desired versus last-confirmed tier; baseline/model status; device inspector with exact 14-feature metadata |
| Traffic & detections | Retained capture windows, counts/bytes, hard-rule names, ML scores, autoencoder suppression, filtering and JSON export |
| Trust intelligence | Device-specific trust history, current baseline generation, rolling windows, adaptive threshold/signatures, anomaly/recovery streaks, IF/AE readiness |
| Network topology | Phase 1 animated LAN → firewall → WAN SVG map, confirmed-tier colors, clickable/keyboard-accessible nodes, pause/reduced motion, device pagination; explicitly not a discovery scan |
| Audit trail | Search/filter lifecycle, tier transitions and failures; JSON export of the latest 200 events |
| Gateway health | Capture state/drops, load average (not CPU utilization), process uptime, disk space, Linux available memory and Pi thermal sensor when available |

The console uses Phase 1’s dark navy/purple palette with green TRUSTED, amber CAUTIOUS, red QUARANTINE and indigo WAN paths. Topology dots illustrate policy paths, not measured packet activity. Quarantined paths end at the gateway; pending/unconfirmed paths do not animate. Animation can be paused, respects reduced-motion preferences, and stops when the gateway is unhealthy or a connection becomes stale. Up to ten devices are shown per page; nodes open the device inspector.

Unobserved metrics display unavailable/empty states. Charts never fabricate traffic; no-data is a valid state. Auto-refresh runs every five seconds while the tab is visible and can be paused. A lost connection marks the displayed data stale. Charts use inline SVG generated from safe DOM operations; all labels use text content rather than HTML injection.

## Operator actions

Enrollment, destination/name edits, rebaselining, explicit CAUTIOUS release from quarantine, and device removal use the same serialized backend lifecycle and checked policy application as API operations. Destructive/reset/override actions open a confirmation dialog. Quarantine release requires an operator reason of 5–300 characters, resets trust to .55 and never jumps to TRUSTED. Release does not erase the model or baseline. Rebaseline does not release quarantine.

If enforcement fails, the UI shows an error and refreshes desired versus confirmed state. A request can have durable pending intent even when its HTTP response is 503; the runtime reconciler retries. Device history uses the last confirmed tier observed when the window was processed. Successful `tier_changed` audit records are written only after firewall confirmation. The single bearer token grants operator access; per-user accounts/RBAC from Phase 1 are not implemented.

## Local storage and API additions

- `GET /`: public static connection screen; contains no credentials or state.
- `GET /dashboard`: authenticated compact projection, events and latest 300 windows across devices. Training vectors and model binaries are excluded.
- `GET /devices/<ip>/history?limit=300`: authenticated retained history, bounded to at most 1,000 requested rows (actual per-device retention is 300).
- `PATCH /devices/<ip>`: authenticated `{name,destinations:[...]}` update.
- `POST /devices/<ip>/release`: authenticated `{reason:"..."}` explicit CAUTIOUS release.

SQLite retains up to 300 metadata windows per device and 10,000 total windows. Windows include trust, score, hard-rule reason, counts/bytes and the ordered feature vector. Rebaseline retains history for auditability; the trust chart displays only the current baseline generation. Device deletion cascades its window/model removal after enforcement cleanup; audit records remain under existing bounded retention.

The token stays in JavaScript memory only, is cleared on disconnect, and must be re-entered after a reload. No localStorage/sessionStorage, cookies, service worker, or remote analytics are used. Static responses include a self-only Content Security Policy, frame denial and no-store headers. API state always requires bearer authentication; there are no permissive CORS headers.

## Validation boundary

Backend tests cover dashboard authentication/projection, local asset/security headers, window retention, deletion, editing/release failures, audit records, capture-health reporting and live simulation rejection. Static checks validate DOM bindings, local assets and JavaScript syntax. The wheel build checks packaging. Full browser interaction/visual verification was unavailable in this development session because the browser host was unavailable. Validate desktop/mobile layout, keyboard navigation, dialogs, chart rendering, exports and operator actions in a real browser before commissioning. Linux packet-path tests and physical Pi checks remain separate.


## Pi integration contract

The production dashboard is served by the same native Python/systemd gateway process at loopback port 8080. It requires no separate Node service, Docker container or frontend build on the Pi. `--config /etc/trustedge/gateway.json` supplies the actual LAN, WAN, gateway address and subnet; the topology never reuses Phase 1 Docker addresses as discovered nodes. The packaged static assets work without Internet access. Access from a workstation uses the SSH tunnel above; the demo auto-pair launcher is simulation-only and is rejected for live servers.

Topology colors use **last confirmed enforcement**, while a differing desired tier is marked pending. Unknown or pending paths have no moving dots, and confirmed quarantine paths terminate at the Pi. Dots are illustrative and do not represent a throughput or reachability measurement. Pi polling is capped at one request per five seconds, stops while the tab is hidden, and does not fetch or deserialize model blobs merely to display model readiness. The SVG shows at most ten devices per page and uses no third-party animation engine.

Before deployment, verify the generated wheel includes `trustedge/static/*`, run the ordinary API tests, then perform the Linux network tests and browser acceptance checklist on the actual Pi. Browser visual verification and physical Pi commissioning remain pending; configured topology is not proof of working routing, DNS, NAT or cabling.
