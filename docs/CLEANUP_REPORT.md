# Cleanup report (networking pass)

**Date:** 2026-11-04  
**Policy:** No blanket deletes; no `docker compose down -v`; no `docker system prune --volumes`.

## Removed

| Item | Type | Reason |
| --- | --- | --- |
| Docker network `trustedge_lan` (`10.10.0.0/24`) | Runtime network | Empty, unreferenced; leftover from earlier naming experiment |
| Docker network `trustedge_wan` (`10.20.0.0/24`) | Runtime network | Same |

## Recreated (not deleted data)

| Item | Action | Data impact |
| --- | --- | --- |
| `lab_lan` / `lab_wan` | `docker compose down` then `up` | Networks recreated with `enable_ip_masquerade=false` |
| Lab containers | Recreated | Ephemeral |
| Volume `lab-db` | **Retained** | SQLite baselines/models/tiers preserved |

## Retained (still referenced)

- All `trustedge/` application code and tests  
- `lab/` Compose, Dockerfiles, traffic gens, scripts  
- `deployment/raspberry-pi/**`  
- `deploy/*` native Pi systemd/nft templates  
- `docs/*` reports  
- `lab/results/*` validation artifacts  
- Git working tree / uncommitted Phase 2 work  

## Not removed (looked old but still used or unsafe)

- `deploy/pi.example.json`, `bootstrap.nft`, systemd units — production path  
- Prior `lab/results/live_three_window_latest.json` — evidence  
- Device container images — rebuilt in place, not pruned  

## Operator note

Disposable only after review: local `__pycache__/`, `.pytest_cache/`, editor swap files. None were bulk-deleted in this pass.
