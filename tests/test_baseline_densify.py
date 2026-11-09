"""Regression: baseline volume densification for IF recovery."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

import numpy as np

from trustedge import detection
from trustedge.features import extract
from trustedge.registry import new_device
from trustedge.simulation import attack_fixture

IP = '172.20.0.10'
FIXTURE = Path(__file__).parent / 'fixtures' / 'laptop_baseline_pi.json'
CAMERA_FIXTURE = Path(__file__).parent / 'fixtures' / 'camera_baseline_pi.json'


class BaselineDensifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = json.loads(FIXTURE.read_text())
        cls.baseline = data['baseline']
        cls.device = new_device(
            IP, data['name'], device_type=data['type'], rate=data['rate'])
        cls.device['model_contamination'] = 0.0125
        cls.device['epoch'] = data['epoch']
        cls.device['generation'] = data['generation']

    def test_densify_only_uses_baseline_hull_and_bounded_volume(self):
        X = np.asarray(self.baseline, dtype=float)
        Y = detection.densify_baseline_vectors(X)
        self.assertGreater(Y.shape[0], X.shape[0])
        self.assertEqual(Y.shape[1], 14)
        self.assertLessEqual(float(Y[:, 0].max()), float(X[:, 0].max()) * 2.0 + 1e-6)
        self.assertTrue(np.isfinite(Y).all())
        # SYN envelope stays below a defensible multiple of the baseline max.
        self.assertLessEqual(float(Y[:, 6].max()), float(X[:, 6].max()) * 2.5 + 1e-6)

    def test_default_train_if_unchanged_without_flag(self):
        bundle = detection.train_if(self.baseline, self.device)
        self.assertNotIn('densified', bundle['calibration'])
        for key in ('baseline_mean', 'baseline_min', 'baseline_std', 'name'):
            self.assertIn(key, bundle['calibration'])

    def test_densify_fixes_pi_laptop_high_volume_false_positive(self):
        """Real Pi evidence: steady-state ~65pkt windows scored ~0.73 before densify."""
        plain = detection.train_if(self.baseline, self.device, densify_volume_tail=False)
        dense = detection.train_if(self.baseline, self.device, densify_volume_tail=True)
        self.assertTrue(dense['calibration'].get('densified'))
        X = np.asarray(self.baseline, float)
        i = int(np.argmax(X[:, 0]))
        live = X[i].copy()
        live[0] = 65.0
        live[1] = 65.0 * live[7]
        live[6] = max(live[6], 9.0)
        live[3] = 0.88
        live[12] = 2.3
        plain_score = detection.isolation_score(plain, live)
        dense_score = detection.isolation_score(dense, live)
        self.assertGreaterEqual(plain_score, detection.ANOMALY_THRESHOLD)
        self.assertLess(dense_score, detection.NOISE_FLOOR)
        # Baseline high-volume tail itself must not remain a hard anomaly after densify.
        self.assertLess(
            detection.isolation_score(dense, X[i]), detection.ANOMALY_THRESHOLD)

    def test_hard_rules_still_fire_after_densify(self):
        detection.train_if(self.baseline, self.device, densify_volume_tail=True)
        for kind, rule in (
            ('data_exfil', 'VOLUME_ANOMALY'),
            ('port_scan', 'PORT_SCAN'),
            ('syn_flood', 'SYN_FLOOD'),
        ):
            pkts = attack_fixture(IP, kind)
            self.assertEqual(detection.hard_rule_check(extract(pkts, 60), pkts), rule)


class CameraDensifyTests(unittest.TestCase):
    """Pi living-room camera: high-load IAT compression false-positives after freeze."""

    @classmethod
    def setUpClass(cls):
        data = json.loads(CAMERA_FIXTURE.read_text())
        cls.data = data
        cls.baseline = data['baseline']
        cls.device = new_device(
            '172.20.0.11', data['name'], device_type=data['type'], rate=data['rate'])
        cls.device['epoch'] = data['epoch']
        cls.device['generation'] = data['generation']
        cls.failing_live = data['failing_live']
        cls.ok_live = data['ok_live']

    def test_densify_covers_camera_high_load_iat_jitter(self):
        plain = detection.train_if(self.baseline, self.device, densify_volume_tail=False)
        dense = detection.train_if(self.baseline, self.device, densify_volume_tail=True)
        self.assertTrue(dense['calibration'].get('densified'))
        self.assertEqual(len(dense['calibration']['baseline_feature_max']), 14)
        # Recorded Pi streaming windows with IAT below the sparse baseline floor
        # must not remain CAUTIOUS-threshold anomalies after densify.
        for row in self.failing_live:
            feats = row['features']
            plain_score = detection.isolation_score(plain, feats)
            dense_score = detection.isolation_score(dense, feats)
            self.assertLess(
                dense_score, detection.ANOMALY_THRESHOLD,
                msg=f"ts={row['ts']} plain={plain_score} dense={dense_score} feats0,1,3,6={feats[0],feats[1],feats[3],feats[6]}")
        # Steady in-hull streaming windows stay under the CAUTIOUS threshold.
        for row in self.ok_live:
            self.assertLess(
                detection.isolation_score(dense, row['features']),
                detection.ANOMALY_THRESHOLD)

    def test_camera_densify_still_flags_syn_only_quarantine_pattern(self):
        dense = detection.train_if(self.baseline, self.device, densify_volume_tail=True)
        # All-SYN 74-byte probes observed while quarantined must remain anomalous.
        syn_only = list(self.baseline[0])
        syn_only[0] = 40.0
        syn_only[1] = 2960.0
        syn_only[6] = 40.0
        syn_only[7] = 74.0
        syn_only[3] = 0.5
        syn_only[12] = 1.0
        # Densified IF must still treat all-SYN probes as clearly elevated; exact
        # hard-rule SYN_FLOOD coverage is asserted separately.
        self.assertGreaterEqual(
            detection.isolation_score(dense, syn_only), detection.NOISE_FLOOR + 0.1)

    def test_camera_densify_keeps_nonvolume_diagnostic_detectable(self):
        plain = detection.train_if(self.baseline, self.device, densify_volume_tail=False)
        dense = detection.train_if(self.baseline, self.device, densify_volume_tail=True)
        base = list(max(self.baseline, key=lambda r: r[1]))
        base[4] = 4.0
        base[5] = 3.0
        base[13] = 2.0
        self.assertGreaterEqual(
            detection.isolation_score(plain, base), detection.ANOMALY_THRESHOLD)
        self.assertGreaterEqual(
            detection.isolation_score(dense, base), detection.ANOMALY_THRESHOLD)
        # AE must not suppress a diagnostic envelope hit on a densified model.
        detection.train_ae(dense, self.baseline[:20])
        value, suppressed = detection.score(dense, base)
        self.assertFalse(suppressed)
        self.assertGreaterEqual(value, detection.ANOMALY_THRESHOLD)

    def test_camera_hard_rules_still_fire_after_densify(self):
        detection.train_if(self.baseline, self.device, densify_volume_tail=True)
        for kind, rule in (
            ('data_exfil', 'VOLUME_ANOMALY'),
            ('port_scan', 'PORT_SCAN'),
            ('syn_flood', 'SYN_FLOOD'),
        ):
            pkts = attack_fixture('172.20.0.11', kind)
            self.assertEqual(detection.hard_rule_check(extract(pkts, 60), pkts), rule)


if __name__ == '__main__':
    unittest.main()
