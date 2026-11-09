import importlib.util
import json
import logging
from pathlib import Path
import tempfile
import threading
import unittest
from collections import defaultdict
from unittest.mock import patch
import joblib
import numpy as np
from numpy.testing import assert_allclose
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from trustedge import detection
from trustedge.features import Packet, extract, FEATURE_SCHEMA
from trustedge.registry import new_device
from trustedge.storage import Storage
from trustedge.service import Gateway
from trustedge.policy import SimulationPolicy
from trustedge.simulation import fixture
from trustedge.import_phase1 import import_device

IP = '192.168.50.2'


def reference(temp):
    spec = importlib.util.spec_from_file_location('phase1_oracle', Path(__file__).parent / 'fixtures/phase1_reference.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.np, mod.joblib = np, joblib
    mod.StandardScaler, mod.IsolationForest, mod.MLPRegressor = StandardScaler, IsolationForest, MLPRegressor
    mod.profiles_lock = threading.RLock()
    mod.log, mod.MODEL_DIR = logging.getLogger('oracle'), temp
    mod.DEVICE_PROFILES = {IP: {'name': 'camera', 'type': 'iot-camera', 'rate': 6}}
    mod.DEVICE_TYPE_PROFILES = {k: {'contamination': v} for k,v in detection.CONTAMINATION.items()}
    for name in ('models', 'scalers', 'ae_models', 'ae_scalers', 'ae_thresholds', 'calibration'):
        setattr(mod, name, {})
    mod.baseline_data, mod.rolling_normal_buffer = defaultdict(list), defaultdict(list)
    mod.trust_scores = {IP: .75}
    mod.NOISE_FLOOR = .5
    mod.HARD_RULE_SYN_FLOOD_PKTS, mod.HARD_RULE_VOLUME_PKTS = 100, 5000
    mod.HARD_RULE_ENTROPY_SCAN, mod.HARD_RULE_VPN_PKT_MIN = 3.5, 10
    mod.VPN_PORTS = detection.VPN_PORTS
    return mod


def vectors():
    rng = np.random.default_rng(12)
    return np.abs(rng.normal(size=(50, 14))) + np.arange(14)


class Phase1ParityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ref = reference(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()

    def test_exact_feature_order_and_values(self):
        packets = [Packet(IP, f'192.0.2.{i%3+1}', 60+i*10, ('tcp','udp','icmp')[i%3],
                          80+i%4, i%3 == 0, timestamp=100+i*i*.01,
                          sport=1234, tcp_flags='SA' if i%3 == 0 else '') for i in range(30)]
        original = [dict(timestamp=p.timestamp, size=p.size, dport=p.port, dst=p.dst,
                         proto={'tcp':6,'udp':17,'icmp':1}[p.protocol], tcp_flags=p.tcp_flags)
                    for p in packets]
        assert_allclose(extract(packets, 60), self.ref.extract_features(original), atol=1e-14)
        self.assertEqual(len(extract(packets, 60)), 14)
        self.assertIsNone(extract([], 60))
        with self.assertRaises(ValueError):
            extract([Packet(IP, '192.0.2.1', 60, 'tcp')], 60)

    def test_isolation_forest_training_and_calibration_match(self):
        X = vectors()
        self.ref.baseline_data[IP] = X.tolist()
        self.ref.train_model_for_device(IP)
        bundle = detection.train_if(X, new_device(IP, 'camera', device_type='iot-camera', rate=6))
        self.assertEqual(bundle['calibration'], self.ref.calibration[IP])
        samples = np.vstack([X[:5], X[0] * 5])
        assert_allclose(bundle['model'].score_samples(bundle['scaler'].transform(samples)),
                        self.ref.models[IP].score_samples(self.ref.scalers[IP].transform(samples)), atol=0)
        for row in samples:
            self.assertEqual(detection.score(bundle, row), (self.ref.score_features(IP, row), False))

    def test_autoencoder_training_threshold_and_suppression_match(self):
        X = vectors()
        self.ref.baseline_data[IP] = X.tolist()
        self.ref.train_model_for_device(IP)
        self.ref.rolling_normal_buffer[IP] = X.tolist()
        self.ref.train_ae_for_device(IP)
        bundle = detection.train_if(X, new_device(IP, 'camera', device_type='iot-camera', rate=6))
        detection.train_ae(bundle, X)
        self.assertEqual(bundle['ae_model'].hidden_layer_sizes, (6,3,6))
        self.assertEqual(bundle['calibration']['ae_threshold'], self.ref.ae_thresholds[IP])
        for row in np.vstack([X[:10], X[0] * 5]):
            expected = self.ref.second_layer_refine(IP, self.ref.score_features(IP, row), row)
            self.assertEqual(detection.score(bundle, row), expected)

    def test_autoencoder_suppression_and_passthrough_branches(self):
        X = vectors()
        bundle = detection.train_if(X, new_device(IP, 'camera'))
        detection.train_ae(bundle, X)
        scaled = bundle['ae_scaler'].transform(X)
        errors = np.mean((scaled - bundle['ae_model'].predict(scaled))**2, axis=1)
        clean = X[np.argmin(errors)]
        c = bundle['calibration']
        raw = c['baseline_mean'] - .9 * max(abs(c['baseline_min'] - c['baseline_mean']), .001)
        with patch.object(bundle['model'], 'score_samples', return_value=np.array([raw])):
            self.assertEqual(detection.score(bundle, clean), (0., True))
            self.assertEqual(detection.score(bundle, X[0] * 100), (.9, False))

    def test_hard_rule_boundaries_and_source_vpn_port_match(self):
        groups = [fixture(IP, True),
                  [Packet(IP, '192.0.2.1', 60, 'tcp', 443, True, i) for i in range(100)],
                  [Packet(IP, '192.0.2.1', 60, 'tcp', 443, True, i) for i in range(101)],
                  [Packet(IP, '192.0.2.1', 60, 'udp', 443, timestamp=i, sport=51820) for i in range(10)],
                  [Packet(IP, '192.0.2.1', 60, 'udp', 53, timestamp=i) for i in range(5001)]]
        for packets in groups:
            features = extract(packets, 60)
            original = [dict(dport=p.port, sport=p.sport) for p in packets]
            attack, rule = self.ref.hard_rule_check(features, original)
            self.assertEqual(detection.hard_rule_check(features, packets), rule)
            self.assertEqual(bool(rule), attack)

    def test_trust_ewma_and_noise_floor_match(self):
        from trustedge.trust import evaluate
        d = new_device(IP, 'camera')
        for score, suppressed in ((.2, False), (.6, False), (.9, False), (0., True), (0., False)):
            expected = self.ref.update_trust(IP, score, suppressed, False)
            evaluate(d, score, False, suppressed)
            self.assertEqual(d['trust'], expected)


class ModelLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / 'local.sqlite')
        self.store = Storage(self.path, 'simulation')
        self.g = Gateway(self.store, SimulationPolicy())
        self.g.register(IP, 'camera')
    def tearDown(self):
        self.store.close()
        self.temp.cleanup()
    def train(self):
        for _ in range(50):
            self.g.window(IP, fixture(IP), 60)
    def test_restart_preserves_model_scores_and_rebaseline_removes_artifacts(self):
        self.train()
        d = self.store.devices()[IP]
        score = detection.score(self.g.detector.load(d), extract(fixture(IP),60))
        blob = self.store.model(IP)
        self.store.close()
        self.store = Storage(self.path, 'simulation')
        self.g = Gateway(self.store, SimulationPolicy())
        self.assertEqual(blob, self.store.model(IP))
        self.assertEqual(score, detection.score(self.g.detector.load(self.store.devices()[IP]), extract(fixture(IP),60)))
        self.g.rebaseline(IP)
        self.assertIsNone(self.store.model(IP))
        self.assertEqual(self.store.devices()[IP]['rolling'], [])
        self.train()
        self.g.delete(IP)
        self.assertIsNone(self.store.model(IP))

    def test_missing_or_incompatible_model_is_not_silently_replaced(self):
        self.train()
        with self.store.transaction():
            self.store.delete_model(IP)
        with self.assertRaises(detection.DetectionError):
            Gateway(self.store, SimulationPolicy())
        self.g.rebaseline(IP)
        self.train()
        d = self.store.devices()[IP]
        bundle = self.g.detector.load(d)
        bundle['schema'] = 'old-12-feature'
        with self.store.transaction():
            self.g.detector.save(d, bundle)
        with self.assertRaises(detection.DetectionError):
            Gateway(self.store, SimulationPolicy())
        # A durable deletion can still complete even if its model is damaged.
        d['deleting'] = True
        with self.store.transaction():
            self.store.save(d)
        recovered = Gateway(self.store, SimulationPolicy())
        recovered.reconcile()
        self.assertNotIn(IP, self.store.devices())
        self.assertIsNone(self.store.model(IP))

    def test_training_failure_rolls_back_baseline_and_marks_detection_unready(self):
        for _ in range(49):
            self.g.window(IP, fixture(IP), 60)
        before = self.store.devices()[IP]
        with patch('trustedge.detection.train_if', side_effect=ValueError('training failed')):
            with self.assertRaises(detection.DetectionError):
                self.g.window(IP, fixture(IP), 60)
        self.assertEqual(self.store.devices()[IP], before)
        self.assertIsNone(self.store.model(IP))
        self.g.reconcile()
        self.assertFalse(self.g.status()['ready'])
        self.g.window(IP, fixture(IP), 60)
        self.assertTrue(self.g.status()['ready'])

    def test_old_five_feature_baseline_is_safely_reset(self):
        d = self.store.devices()[IP]
        d.pop('feature_schema')
        d.update(baseline=[[1]*5], desired_tier='TRUSTED', applied_tier='TRUSTED', trust=.85)
        with self.store.transaction():
            self.store.save(d)
        self.g = Gateway(self.store, SimulationPolicy())
        self.g.reconcile()
        d = self.store.devices()[IP]
        self.assertEqual(d['feature_schema'], FEATURE_SCHEMA)
        self.assertEqual((d['baseline'], d['trust'], d['applied_tier']), ([], .85, 'CAUTIOUS'))

    def test_import_preserves_scores_and_rejects_incomplete_ae(self):
        ref = reference(self.temp.name)
        ref.baseline_data[IP] = vectors().tolist()
        ref.train_model_for_device(IP)
        ref.rolling_normal_buffer[IP] = vectors().tolist()
        ref.train_ae_for_device(IP)
        Path(self.temp.name, 'calibration.json').write_text(json.dumps(ref.calibration))
        import_device(self.store, IP, self.temp.name)
        d = self.store.devices()[IP]
        bundle = self.g.detector.load(d)
        for row in vectors()[:5]:
            expected = ref.second_layer_refine(IP, ref.score_features(IP, row), row)
            self.assertEqual(detection.score(bundle, row), expected)
        self.assertFalse(d['learning'])
        self.assertEqual(d['desired_tier'], 'CAUTIOUS')
        target = '192.168.50.3'
        self.g.register(target, 'mapped camera')
        import_device(self.store, target, self.temp.name, source_ip=IP)
        mapped = self.store.devices()[target]
        self.assertEqual(mapped['model_contamination'], .0167)
        self.assertEqual(detection.score(self.g.detector.load(mapped), vectors()[0]),
                         detection.score(bundle, vectors()[0]))
        before = self.store.model(IP)
        Path(self.temp.name, 'ae_scaler_192_168_50_2.pkl').unlink()
        with self.assertRaises(detection.DetectionError):
            import_device(self.store, IP, self.temp.name)
        self.assertEqual(before, self.store.model(IP))

    def test_baseline_if_frozen_across_100_200_300_windows(self):
        """Baseline IF+scaler+calibration must not change after AE fits or many windows."""
        import pickle
        self.train()
        d = self.store.devices()[IP]
        self.assertEqual(len(d['baseline']), 50)
        self.assertFalse(d['learning'])
        # Reach first AE fit (needs 15 rolling normals) without touching IF.
        for _ in range(20):
            self.g.window(IP, fixture(IP), 60)
        d = self.store.devices()[IP]
        bundle = self.g.detector.load(d)
        self.assertIn('ae_model', bundle)
        self.assertGreaterEqual(d['detection_windows'], 15)
        if_fp = (
            pickle.dumps(bundle['model'], protocol=5),
            pickle.dumps(bundle['scaler'], protocol=5),
            bundle['calibration']['baseline_mean'],
            bundle['calibration']['baseline_min'],
            bundle['calibration']['baseline_std'],
            bundle['identity'],
        )
        baseline_rows = list(d['baseline'])
        baseline_scores = [detection.isolation_score(bundle, row) for row in baseline_rows]
        # Original baseline must not look widely anomalous under its own model.
        self.assertLess(sum(1 for s in baseline_scores if s >= detection.NOISE_FLOOR) / len(baseline_scores), .25)

        for target in (100, 200, 300):
            while self.store.devices()[IP]['detection_windows'] < target:
                self.g.window(IP, fixture(IP), 60)
            d = self.store.devices()[IP]
            bundle = self.g.detector.load(d)
            self.assertEqual(d['detection_windows'], target)
            self.assertEqual(len(d['rolling']), 50)
            self.assertIn('ae_model', bundle)
            self.assertEqual(
                (
                    pickle.dumps(bundle['model'], protocol=5),
                    pickle.dumps(bundle['scaler'], protocol=5),
                    bundle['calibration']['baseline_mean'],
                    bundle['calibration']['baseline_min'],
                    bundle['calibration']['baseline_std'],
                    bundle['identity'],
                ),
                if_fp,
            )
            self.assertEqual(bundle['identity'], (d['epoch'], d['generation']))
            self.assertEqual(
                [detection.isolation_score(bundle, row) for row in baseline_rows],
                baseline_scores,
            )

    def test_each_device_keeps_own_baseline_model_identity(self):
        other = '192.168.50.3'
        self.g.register(other, 'laptop', device_type='laptop')
        self.train()
        for _ in range(50):
            self.g.window(other, fixture(other), 60)
        a = self.g.detector.load(self.store.devices()[IP])
        b = self.g.detector.load(self.store.devices()[other])
        self.assertNotEqual(a['identity'], b['identity'])
        self.assertEqual(a['identity'][1], self.store.devices()[IP]['generation'])
        self.assertEqual(b['identity'][1], self.store.devices()[other]['generation'])
        self.assertNotEqual(self.store.model(IP), self.store.model(other))
        # Advance past former refit boundaries; identities stay device-local.
        for _ in range(100):
            self.g.window(IP, fixture(IP), 60)
            self.g.window(other, fixture(other), 60)
        a2 = self.g.detector.load(self.store.devices()[IP])
        b2 = self.g.detector.load(self.store.devices()[other])
        self.assertEqual(a2['identity'], a['identity'])
        self.assertEqual(b2['identity'], b['identity'])
