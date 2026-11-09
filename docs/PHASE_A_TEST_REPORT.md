# Phase A test report

Date: 2026-11-09

## Command

```bash
cd ~/cursor/trustedge-phase2-integration
.venv/bin/python -m unittest discover -s tests
```

## Result

| Outcome | Count |
|---------|------:|
| Passed | 96 |
| Skipped | 2 |
| Failed | 0 |

Skipped tests (require Linux root + nft + `TRUSTEDGE_NFT_TESTS=1`):

- `test_nft_linux.KernelPolicyTests.test_real_pi_gateway_packet_path`
- `test_nft_linux.KernelPolicyTests.test_repeated_atomic_replacement_and_failed_transaction_preserves_rules`

## Frozen ML hashes verified after tests

- `detection.py` = `01fa5d2fb926d16445ff970af44bf8ddb84c883e85cd566f8e0a26a25edee720`
- `simulation.py` = `41c82572add8d79e3ea2479891b2c190a1a9f375e81c9e90ed151851525b8fc4`

## New Phase A coverage

- Local-only cloud telemetry stubs / no CDN assets
- SQLite schema v2 migration + reopen persistence
- Enforcement audit + restart survival
- Audit-log filtering not dominated by window events
- Device stale / enrollment view fields
