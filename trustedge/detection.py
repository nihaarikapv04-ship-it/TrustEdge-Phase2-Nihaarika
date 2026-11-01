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

def train_if(vectors, device):
    X = np.asarray(vectors)
    scaler = StandardScaler()
    scaled = scaler.fit_transform(X)
    contamination = device.get('model_contamination', CONTAMINATION.get(device.get('device_type')))
    if contamination is None:
        contamination = max(.01, min(.05, .1 / device.get('rate', 5)))
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(scaled)
    raw = model.score_samples(scaled)
    return dict(model=model, scaler=scaler, calibration=dict(
        name=device['name'], baseline_min=float(np.min(raw)),
        baseline_mean=float(np.mean(raw)), baseline_std=float(np.std(raw))),
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

def isolation_score(bundle, features):
    X = np.asarray(features).reshape(1, -1)
    raw = bundle['model'].score_samples(bundle['scaler'].transform(X))[0]
    c = bundle['calibration']
    value = round(float(np.clip((c['baseline_mean'] - raw) /
                  max(abs(c['baseline_min'] - c['baseline_mean']), .001), 0, 1)), 4)
    return value

def score(bundle, features):
    value = isolation_score(bundle, features)
    X = np.asarray(features).reshape(1, -1)
    if value <= NOISE_FLOOR or 'ae_model' not in bundle:
        return value, False
    scaled = bundle['ae_scaler'].transform(X)
    error = float(np.mean((scaled - bundle['ae_model'].predict(scaled)) ** 2))
    return (0., True) if error <= bundle['calibration']['ae_threshold'] else (value, False)

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
        # Preserve reference rolling collection and anchor-preserving refit.
        device['detection_windows'] += 1
        threshold = ANOMALY_THRESHOLD if device['desired_tier'] == 'CAUTIOUS' else NOISE_FLOOR
        if value < threshold:
            device['rolling'] = (device['rolling'] + [features])[-50:]
        buf = device['rolling']
        changed = False
        if len(buf) >= 15 and 'ae_model' not in bundle:
            train_ae(bundle, buf)
            changed = True
        if device['detection_windows'] % 100 == 0 and len(buf) >= 10:
            anchors = {k: bundle['calibration'][k] for k in ('baseline_min', 'baseline_mean')}
            bundle = train_if(buf, device)
            bundle['calibration'].update(anchors)
            train_ae(bundle, buf)
            changed = True
        if changed:
            self.save(device, bundle)
        return value, False, suppressed, 'ml'
