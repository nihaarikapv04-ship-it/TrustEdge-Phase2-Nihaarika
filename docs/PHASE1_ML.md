# Phase 1 ML integration

Source: [Phase 1 pipeline.py](https://github.com/nehadevarasetty/TrustEdge-firewall/blob/ae8ecc7f64e1b0838dd13f7281ee53bdca143c75/containers/firewall/pipeline.py). The reference checkout is read-only and has never been pushed. Importing the old pipeline itself would start globals, create files and couple cloud/API/enforcement behavior; the new adapter ports the ML math without those side effects.

## What is preserved

- The exact 14-feature order: packet count, total frame bytes, duration, mean inter-arrival time, distinct destination ports, distinct destinations, SYN count, mean frame size, population standard deviation of sizes, TCP/UDP/ICMP fractions, population standard deviation of inter-arrival times, and destination-port Shannon entropy (including the original `1e-9` smoothing).
- Scapy metadata fields: full `len(packet)` including captured link headers, callback timestamp, IP protocol, source/destination ports, and TCP flags. The previous tcpdump parser's transport byte counts and absent timestamps were incompatible and have been replaced. Captured packets are immediately reduced to metadata; Scapy uses `store=False`.
- Per-device StandardScaler and IsolationForest: 100 estimators, seed 42, original device-type contamination values (custom defaults to .020), calibrated normalization using `baseline_mean`/`baseline_min`, spread floor .001 and four-decimal scores.
- Autoencoder: sklearn `MLPRegressor`, `(6,3,6)` hidden layers, `tanh`, Adam, max 1000 iterations, tolerance `1e-5`, adaptive learning rate starting at `.01`, seed 42. Reconstruction threshold is `max(mean_error + 2.5*std_error, .02)`. It suppresses scores above .50 when reconstruction error is within threshold and otherwise preserves the IF score.
- Hard rules: SYN count >100 with fewer than ten approximate ACKs; packet count >5000; destination-port entropy >3.5; at least ten packets using the original VPN-port set on either source or destination.
- Fifty baseline windows and at least five packets in an eligible window. Rolling normal buffer of 50, first AE training at 15 normal detection windows, refit every 100 detection windows with at least ten buffered windows. Original calibration mean/min anchors survive a rolling IF refit. CAUTIOUS collection uses the original .70 threshold; TRUSTED uses .50.
- Trust math now includes Phase 1's .50 noise floor, .2 degradation, .4 normal recovery and .7 AE-suppressed recovery, rounded to four decimals.

The frozen functions under `tests/fixtures/phase1_reference.py` serve only as an offline parity oracle. Tests compare actual trained estimators, calibration, scores, reconstruction behavior, feature values and hard-rule boundaries with the original functions. The source repository is not needed to run these tests.

## Gateway safety boundaries

Phase 2 owns lifecycle and policy decisions while retaining Phase 1's three-window ML downgrade and ten-window recovery gates, plus Phase 1's immediate hard-rule quarantine (trust forced to 0.1). Adaptive signature thresholds and validation are persisted in SQLite using streaming moments. Explicit CAUTIOUS enrollment, operator-only quarantine release, and one-tier non-hard ML downgrades remain intentional Phase 2 corrections (see [POLICY_CORRECTIONS.md](POLICY_CORRECTIONS.md)). Hard rules also run during learning. Quarantined traffic never trains or grants recovery, and no address has Phase 1's infrastructure-IP detection bypass. Feature preprocessing, IF/AE training and score calculations above are preserved.

The new default replaces the temporary five-feature statistical detector. Existing five-feature baselines are discarded with an audit event on startup; trust and quarantine remain, and previously TRUSTED devices become CAUTIOUS while collecting a compatible baseline. This prevents feeding incompatible data to the Phase 1 models.

Model bundles are serialized into local SQLite, alongside per-device baseline/rolling state. Model writes, training progress and device state commit in one transaction. Rebaselining removes the bundle and increments the generation; deletion cascades model removal after successful firewall cleanup. Models are bound to enrollment identity and baseline generation. Missing/corrupt/incompatible persisted models fail explicitly, with no statistical or cloud fallback. A failed training window rolls back its state and reports detection unavailable; policy retries cannot hide that ML failure.

## Use separately saved Phase 1 models

The GitHub tree contains model training code but no trained artifacts. For a device with saved artifacts, use a local directory containing:

```text
model_172_20_0_10.pkl
scaler_172_20_0_10.pkl
ae_model_172_20_0_10.pkl      # optional, both AE files required together
ae_scaler_172_20_0_10.pkl
calibration.json
```

Calibration must contain that original IP's `baseline_mean`, `baseline_min`, and `baseline_std`; an AE additionally requires `ae_threshold`. Models with a different feature dimension or scikit-learn version are rejected rather than silently reused.

1. Install the dependencies and enroll the target device using the regular local API.
2. Stop the gateway process before import; do not import concurrently with capture.
3. Import from your trusted local directory, optionally mapping the old simulated IP to a real reserved LAN IP:

```sh
.venv/bin/python -m trustedge.import_phase1 \
  --database /var/lib/trustedge/live.sqlite --mode live \
  --ip 192.168.50.2 --source-ip 172.20.0.10 \
  --models /path/to/trusted/phase1-models --trust-local-artifacts
```

4. Restart the gateway. It validates models, reapplies durable policy, and starts capture. Inspect `/status` (`detector: "phase1"`) and `/events` for import and scoring details.

Import retains the fitted IF contamination setting for subsequent local refits and preserves trust and quarantine, clears stale learning buffers, increments the generation, and never grants a policy upgrade. Without artifacts, the same Phase 1 training algorithm trains new local weights from approved clean traffic; those weights are not the previously trained Phase 1 weights. Models trained on simulated Phase 1 traffic may need rebaselining on real hardware even if their dimensions match.

The reference pins scikit-learn 1.6.1; this project uses the same version. Use Python 3.11 and reproduce the original NumPy/SciPy/joblib versions for importing existing artifacts where available. The reference did not pin those libraries. Scikit-learn does not support cross-version model loading, and joblib/pickle loading can execute code, so the importer is offline and requires an explicit trusted-artifact flag. See the [official model persistence guidance](https://scikit-learn.org/1.6/model_persistence.html). No artifact-loading API endpoint exists.
