# Intentional policy corrections vs Phase 1

Phase 1 hard-rule quarantine and EWMA math are restored to match reference
`ae8ecc7` (`TrustEdge-firewall`). The items below are **deliberate** Phase 2
security/orchestration corrections. They are not silent deviations.

| Topic | Phase 1 reference | Phase 2 correction | Why |
| --- | --- | --- | --- |
| Enrollment starting tier | `TRUSTED` while learning | `CAUTIOUS` while learning | Unknown/new devices must not get broad forwarding before a baseline exists |
| Hard-rule response | Trust forced to `0.1`; immediate jump to `QUARANTINE` | Same (restored) | Preserve Phase 1 firewall behaviour |
| Non-hard ML downgrade | Set tier to computed `target` after streak | One tier per validated 3-window streak (`TRUSTED→CAUTIOUS→QUARANTINE`) | Avoid skipping CAUTIOUS when trust collapses via ML alone |
| Quarantine recovery | Ten normal windows can raise tier | No automatic recovery; audited `POST /devices/<ip>/release` only | Restricted traffic must not “look healthy” and self-release |
| Learning → TRUSTED | Possible once trust recovers | Learning devices capped at `CAUTIOUS` until baseline completes | Baseline must finish before broad access |
| Enforcement backend | `iptables` FORWARD rules | Atomic owned `nftables` table with checked return codes | Safer replacement/rollback on Pi |
| CAUTIOUS / QUARANTINE DNS | CAUTIOUS: UDP/53 `@10/min`; QUARANTINE: UDP/53 unlimited | Same rates in nftables (`10/minute` / unlimited) | Restored Phase 1 DNS enforcement (was briefly `10/second`) |
| CAUTIOUS HTTP(S) scope | Any destination :80/:443 | Only enrolled `destinations` :80/:443 | Explicit allow-list of known sinks |
| Unknown/deleted devices | Rules flushed; default FORWARD historically permissive in lab | Explicit deny for unknown LAN sources | Zero-trust default |
| Baseline windows | `BASELINE_WINDOWS = 50` | Same (`50`) | Keep Phase 1 parity (not 60) |

Automated parity coverage: `tests/test_phase1_policy.py` (hard-rule quarantine,
CAUTIOUS/QUARANTINE gates, enrollment starting state, recovery/release).
ML feature/IF/AE/EWMA parity remains in `tests/test_phase1_ml.py`.
