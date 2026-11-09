"""Local Phase 1 Isolation Forest + sklearn MLP autoencoder integration.

Ported from reference ae8ecc7f64e1b0838dd13f7281ee53bdca143c75.
Model training/scoring parameters and feature ordering are preserved. The service
owns enforcement and never imports the monolithic reference pipeline.
"""
import pickle
import warnings
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.exceptions import InconsistentVersionWarning
from .features import FEATURE_SCHEMA
from .signatures import new_state

BASELINE_WINDOWS = 50
NOISE_FLOOR = .50
ANOMALY_THRESHOLD = .70
VPN_PORTS = {51820, 1194, 500, 4500, 1701, 1723, 4789}
CONTAMINATION = {'laptop': .0125, 'iot-camera': .0167, 'iot-thermo': .05,
                 'smartphone': .020, 'printer': .05, 'smart-lock': .05,
                 'smart-hub': .025, 'nas': .010, 'voip-phone': .015, 'custom': .020}
# Diagnostic axes that stay near-constant on many IoT baselines. Volume densify
# can drown IF sensitivity on these; densified models retain a baseline-max
# envelope so clear departures remain detectable without lowering thresholds.
DIAGNOSTIC_FEATURE_IDX = (4, 5, 13)  # unique_dports, unique_destinations, port entropy

class DetectionError(RuntimeError):
    pass

def hard_rule_check(features, packets):
    total, syn, tcp = features[0], features[6], features[9]
    if syn > 100 and max(total * tcp - syn, 0) < 10:
        return 'SYN_FLOOD'
    if total > 5000:
        return 'VOLUME_ANOMALY'
    if features[13] > 3.5:
        return 'PORT_SCAN'
    vpn = sum(p.port in VPN_PORTS or p.sport in VPN_PORTS for p in packets)
    return f'VPN_TUNNEL_DETECTED({vpn}pkts)' if vpn >= 10 else ''

def _fit_if(X, device, contamination_override=None):
    """Fit IsolationForest + scaler; calibrate raw scores on the provided matrix."""
    scaler = StandardScaler()
    scaled = scaler.fit_transform(X)
    if contamination_override is None:
        contamination = device.get('model_contamination', CONTAMINATION.get(device.get('device_type')))
        if contamination is None:
            contamination = max(.01, min(.05, .1 / device.get('rate', 5)))
    else:
        contamination = float(contamination_override)
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(scaled)
    raw = model.score_samples(scaled)
    return model, scaler, raw, contamination


def densify_baseline_vectors(vectors, rng=None):
    """Expand known-normal baseline vectors without introducing non-baseline traffic.

    IsolationForest with small N and low contamination treats the baseline's own
    high-volume tail as the outlier that defines calibration. When steady-state
    normal traffic later sits in that tail, frozen IF scores stay high. Densify
    by (1) convex combinations of baseline rows and (2) proportional volume
    variants clipped to a bounded envelope above the observed baseline max —
    both derived only from validated baseline vectors.

    High-load IoT streams (cameras) also exhibit burst timing: shorter duration,
    lower IAT, and mild SYN/mean-size drift around the high-byte baseline corner.
    Expand a bounded grid on those corners so legitimate stream jitter is not the
    frozen contamination outlier. Diagnostic port/destination/entropy axes are
    left untouched here; densified calibration keeps a baseline-max envelope so
    clear departures on those axes remain detectable after volume expansion.
    """
    X = np.asarray(vectors, dtype=float)
    if X.ndim != 2 or X.shape[0] < 2:
        return X
    rng = np.random.default_rng(42 if rng is None else rng)
    parts = [X]
    # Convex combinations stay inside the known-normal hull.
    n_mix = min(100, X.shape[0] * 2)
    i0 = rng.integers(0, X.shape[0], size=n_mix)
    i1 = rng.integers(0, X.shape[0], size=n_mix)
    alpha = rng.uniform(0.2, 0.8, size=(n_mix, 1))
    parts.append(alpha * X[i0] + (1.0 - alpha) * X[i1])
    # Volume envelope: scale packet/byte/syn intensity; compress duration/IAT.
    pkt = X[:, 0]
    pkt_max = float(np.max(pkt)) if pkt.size else 0.0
    for factor in (0.75, 1.25, 1.5, 1.75, 2.0):
        if pkt_max > 0 and factor * float(np.median(pkt)) > pkt_max * 2.5:
            continue  # refuse extreme inflation beyond a defensible band
        Y = X.copy()
        Y[:, 0] = np.clip(X[:, 0] * factor, 1.0, None)
        Y[:, 1] = np.clip(X[:, 1] * factor, 0.0, None)
        Y[:, 6] = np.clip(X[:, 6] * factor, 0.0, None)
        if factor >= 1.0:
            Y[:, 2] = np.clip(X[:, 2] / factor, 1e-3, None)
        Y[:, 3] = X[:, 3] / factor
        Y[:, 12] = X[:, 12] / factor
        parts.append(Y)
    # Oversample the full known-normal baseline and its high-load corners.
    # Small-N contamination otherwise reserves legitimate high-load baseline
    # rows as the outlier scale — the Pi camera/laptop failure mode.
    parts.extend([X] * 6)
    hi_rows = []
    for col in (0, 1, 7):
        q = float(np.quantile(X[:, col], 0.5))
        hi = X[X[:, col] >= q]
        if hi.shape[0]:
            parts.extend([hi] * 8)
            hi_rows.append(hi)
    if hi_rows:
        hi = np.unique(np.vstack(hi_rows), axis=0)
        syn_max = float(np.max(X[:, 6])) if X.size else 0.0
        # Burst / volume / SYN / mean-size grid on high-load corners only.
        for vf in (0.8, 0.9, 1.0, 1.1, 1.2, 1.35, 1.5):
            for burst in (1.0, 1.25, 1.5, 1.75, 2.0):
                for syn_f in (1.0, 1.4, 1.8):
                    # mean/std size envelope: Pi camera steady streams reached ~1.22×
                    # baseline mean_size max; keep a bounded headroom below hard rules.
                    for size_f in (0.75, 1.0, 1.15, 1.25, 1.35):
                        Y = hi.copy()
                        Y[:, 0] = np.clip(hi[:, 0] * vf, 1.0, None)
                        Y[:, 1] = np.clip(hi[:, 1] * vf * size_f, 0.0, None)
                        Y[:, 7] = hi[:, 7] * size_f
                        Y[:, 8] = hi[:, 8] * size_f
                        Y[:, 6] = np.clip(hi[:, 6] * syn_f, 0.0, max(syn_max * 2.5, 1.0))
                        Y[:, 2] = np.clip(hi[:, 2] / burst, 1e-3, None)
                        Y[:, 3] = np.clip(hi[:, 3] / burst, 1e-3, None)
                        Y[:, 12] = np.clip(hi[:, 12] / burst, 1e-3, None)
                        parts.append(Y)
        top = X[X[:, 1] >= np.quantile(X[:, 1], 0.9)]
        if top.shape[0]:
            for vf in (0.9, 1.0, 1.1, 1.2, 1.35, 1.5):
                for burst in (1.0, 1.2, 1.5, 1.8, 2.0):
                    for syn_f in (1.0, 1.5, 2.0):
                        for size_f in (1.0, 1.15, 1.25, 1.35):
                            Y = top.copy()
                            Y[:, 0] = np.clip(top[:, 0] * vf, 1.0, None)
                            Y[:, 1] = np.clip(top[:, 1] * vf * size_f, 0.0, None)
                            Y[:, 7] = top[:, 7] * size_f
                            Y[:, 8] = top[:, 8] * size_f
                            Y[:, 6] = np.clip(top[:, 6] * syn_f, 0.0, max(syn_max * 2.5, 1.0))
                            Y[:, 2] = np.clip(top[:, 2] / burst, 1e-3, None)
                            Y[:, 3] = np.clip(top[:, 3] / burst, 1e-3, None)
                            Y[:, 12] = np.clip(top[:, 12] / burst, 1e-3, None)
                            parts.extend([Y] * 2)
    return np.vstack(parts)


def _volume_tail_contamination(X, provisional):
    """True when high IF scores on the baseline concentrate in its volume tail.

    Small-N IsolationForest + low contamination always marks some training rows
    as outliers. Densify only when those outliers are the high-packet tail of an
    otherwise low-volume baseline — the Pi laptop failure mode — not for ordinary
    healthy baselines or abstract synthetic unit-test matrices.
    """
    high = provisional >= ANOMALY_THRESHOLD
    n_high = int(np.sum(high))
    if n_high < 2 or float(np.mean(high)) < 0.06:
        return False
    pkt = np.asarray(X[:, 0], dtype=float)
    median = float(np.median(pkt))
    # Real traffic baselines have meaningful packet counts; reject tiny synthetic features.
    if median < 5.0:
        return False
    high_mean = float(np.mean(pkt[high]))
    p90 = float(np.quantile(pkt, 0.9))
    pkt_max = float(np.max(pkt))
    # Right-skewed volume envelope: rare high-packet rows exist above the bulk.
    if pkt_max < median * 1.6:
        return False
    # Anomalous baseline rows sit in that high-volume tail.
    if not (high_mean >= median * 1.4 and high_mean >= p90 * 0.85):
        return False
    # Packet count should track the provisional anomaly score for this failure mode.
    if float(np.std(pkt)) < 1e-9 or float(np.std(provisional)) < 1e-9:
        return False
    corr = float(np.corrcoef(pkt, provisional)[0, 1])
    return corr >= 0.45


def train_if(vectors, device, densify_volume_tail=False):
    """Train IF+scaler+calibration as one unit from baseline vectors.

    Default path matches Phase 1 training. When ``densify_volume_tail`` is true
    (operator-authorized recovery for a volume-skewed baseline), train on
    baseline-derived densified vectors but always calibrate on the original
    baseline so the unit stays tied to retained known-normal windows.
    """
    X = np.asarray(vectors, dtype=float)
    densified = False
    if densify_volume_tail:
        X_train = densify_baseline_vectors(X)
        # Keep ~one contamination slot after densification so known-normal
        # high-load baseline corners are not re-selected as the outlier scale.
        cont = max(1.0 / float(len(X_train)), 1e-3)
        model, scaler, _raw_train, _contamination = _fit_if(
            X_train, device, contamination_override=cont)
        raw = model.score_samples(scaler.transform(X))
        densified = True
    else:
        model, scaler, raw, _contamination = _fit_if(X, device)
    calibration = dict(
        name=device['name'], baseline_min=float(np.min(raw)),
        baseline_mean=float(np.mean(raw)), baseline_std=float(np.std(raw)))
    if densified:
        calibration['densified'] = True
        # Retain original baseline extrema for diagnostic-axis envelope checks.
        calibration['baseline_feature_max'] = [float(v) for v in np.max(X, axis=0)]
        calibration['baseline_feature_min'] = [float(v) for v in np.min(X, axis=0)]
    return dict(model=model, scaler=scaler, calibration=calibration,
        schema=FEATURE_SCHEMA, sklearn_version=sklearn.__version__, origin='local_training')

def train_ae(bundle, vectors):
    scaler = StandardScaler()
    X = scaler.fit_transform(np.asarray(vectors))
    ae = MLPRegressor(hidden_layer_sizes=(6, 3, 6), activation='tanh',
                      solver='adam', max_iter=1000, tol=1e-5,
                      learning_rate='adaptive', learning_rate_init=.01, random_state=42)
    ae.fit(X, X)
    errors = np.mean((X - ae.predict(X)) ** 2, axis=1)
    bundle.update(ae_model=ae, ae_scaler=scaler)
    bundle['calibration']['ae_threshold'] = float(max(np.mean(errors) + 2.5 * np.std(errors), .02))

def _diagnostic_envelope_hit(bundle, features):
    """True when densified calibration sees a clear diagnostic-axis departure.

    Volume densification widens packet/byte variance and can drown IsolationForest
    splits on near-constant port/destination/entropy axes. The envelope uses only
    retained baseline extrema (never attack traffic) and does not lower thresholds.
    """
    c = bundle.get('calibration') or {}
    if not c.get('densified'):
        return False
    bmax = c.get('baseline_feature_max')
    if not bmax or len(bmax) != 14:
        return False
    feats = np.asarray(features, dtype=float).reshape(-1)
    if feats.size != 14:
        return False
    for idx in DIAGNOSTIC_FEATURE_IDX:
        if float(feats[idx]) > float(bmax[idx]) + 1e-9:
            return True
    return False


def isolation_score(bundle, features):
    X = np.asarray(features).reshape(1, -1)
    raw = bundle['model'].score_samples(bundle['scaler'].transform(X))[0]
    c = bundle['calibration']
    value = round(float(np.clip((c['baseline_mean'] - raw) /
                  max(abs(c['baseline_min'] - c['baseline_mean']), .001), 0, 1)), 4)
    if _diagnostic_envelope_hit(bundle, features):
        value = max(value, ANOMALY_THRESHOLD)
    return value

def score(bundle, features):
    value = isolation_score(bundle, features)
    X = np.asarray(features).reshape(1, -1)
    envelope = _diagnostic_envelope_hit(bundle, features)
    if value <= NOISE_FLOOR or 'ae_model' not in bundle:
        return value, False
    scaled = bundle['ae_scaler'].transform(X)
    error = float(np.mean((scaled - bundle['ae_model'].predict(scaled)) ** 2))
    if error <= bundle['calibration']['ae_threshold']:
        # Do not AE-suppress a clear diagnostic-axis baseline-envelope violation.
        if envelope:
            return value, False
        return (0., True)
    return value, False

def validate(bundle):
    if bundle.get('schema') != FEATURE_SCHEMA:
        raise DetectionError('incompatible model feature schema')
    if bundle.get('sklearn_version') != sklearn.__version__:
        raise DetectionError('model scikit-learn version differs from runtime')
    for key in ('model', 'scaler', 'ae_model', 'ae_scaler'):
        if key in bundle and getattr(bundle[key], 'n_features_in_', None) != 14:
            raise DetectionError(f'{key} must use the Phase 1 14-feature layout')
    if not isinstance(bundle.get('model'), IsolationForest) or not isinstance(bundle.get('scaler'), StandardScaler):
        raise DetectionError('expected Phase 1 IsolationForest and StandardScaler')
    if 'ae_model' in bundle and (not isinstance(bundle['ae_model'], MLPRegressor) or
                               not isinstance(bundle.get('ae_scaler'), StandardScaler)):
        raise DetectionError('expected Phase 1 MLPRegressor and StandardScaler')
    c = bundle.get('calibration', {})
    for key in ('baseline_mean', 'baseline_min', 'baseline_std'):
        if not isinstance(c.get(key), (float, int)) or not np.isfinite(c[key]):
            raise DetectionError('missing or invalid calibration: ' + key)
    if 'ae_model' in bundle and (not np.isfinite(c.get('ae_threshold', float('nan'))) or c['ae_threshold'] < 0):
        raise DetectionError('missing or invalid AE threshold')
    # Also verify fitted input/output compatibility before accepting an import.
    score(bundle, [0.] * 14)

class Phase1Detector:
    def __init__(self, storage):
        self.storage = storage

    def load(self, device):
        blob = self.storage.model(device['ip'])
        if blob is None:
            return None
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error', InconsistentVersionWarning)
                bundle = pickle.loads(blob)
            validate(bundle)
            if bundle.get('identity') != (device['epoch'], device['generation']):
                raise DetectionError('model does not match enrollment/baseline generation')
            return bundle
        except Exception as exc:
            raise DetectionError(f"Cannot load model for {device['ip']}: {exc}") from exc

    def save(self, device, bundle):
        bundle['identity'] = (device['epoch'], device['generation'])
        device['model_info'] = self.model_info(bundle)
        self.storage.save(device)
        self.storage.save_model(device['ip'], pickle.dumps(bundle, protocol=5))

    @staticmethod
    def model_info(bundle):
        return dict(isolation_forest=True, autoencoder='ae_model' in bundle,
                    sklearn_version=bundle['sklearn_version'], feature_count=14,
                    origin=bundle.get('origin','local_training'),
                    ae_threshold=bundle['calibration'].get('ae_threshold'))

    def prepare(self):
        # Old five-feature baselines cannot be used with Phase 1 models.
        for d in self.storage.devices().values():
            if d.get('deleting'):
                continue  # Reconcile must be able to finish deletion of a broken model.
            if d.get('feature_schema') != FEATURE_SCHEMA:
                d.update(model_info=None, signature_state=new_state(), anomaly_streak=0, normal_streak=0, feature_schema=FEATURE_SCHEMA, baseline=[], rolling=[],
                         detection_windows=0, learning=True, streak=0, candidate=None,
                         generation=d['generation']+1)
                if d['desired_tier'] == 'TRUSTED':
                    d['desired_tier'] = 'CAUTIOUS'
                self.storage.delete_model(d['ip'])
                self.storage.save(d)
                self.storage.event(action='feature_schema_reset', ip=d['ip'])
            bundle = self.load(d)
            if bundle is not None and d.get('model_info') != self.model_info(bundle):
                d['model_info'] = self.model_info(bundle)
                self.storage.save(d)
            if not d['learning'] and bundle is None and not d.get('deleting'):
                raise DetectionError(f"Missing persisted model for {d['ip']}; rebaseline explicitly")

    def process(self, device, features, packets):
        rule = hard_rule_check(features, packets)
        if rule:
            return 1., True, False, rule
        if len(packets) < 5:
            return None, False, False, 'insufficient_packets'
        if device['desired_tier'] == 'QUARANTINE':
            return None, False, False, 'quarantined'
        if device['learning']:
            device['baseline'].append(features)
            if len(device['baseline']) >= BASELINE_WINDOWS:
                self.save(device, train_if(device['baseline'], device))
                device['learning'] = False
            return None, False, False, 'learning'
        bundle = self.load(device)
        if bundle is None:
            raise DetectionError('trained model missing; explicit rebaseline required')
        value, suppressed = score(bundle, features)
        # Rolling buffer still feeds first-time AE training. Periodic Isolation
        # Forest refit on rolling traffic is disabled for this release: the
        # baseline IF model, scaler, and calibration stay one consistent unit.
        # train_if may densify a volume-skewed baseline before that freeze.
        device['detection_windows'] += 1
        threshold = ANOMALY_THRESHOLD if device['desired_tier'] == 'CAUTIOUS' else NOISE_FLOOR
        if value < threshold:
            device['rolling'] = (device['rolling'] + [features])[-50:]
        buf = device['rolling']
        if 'ae_model' not in bundle and len(buf) >= 15:
            train_ae(bundle, buf)
            self.save(device, bundle)
        return value, False, suppressed, 'ml'
