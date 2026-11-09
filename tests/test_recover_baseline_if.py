"""Disposable-DB tests for offline baseline IF reconstruction (laptop recovery)."""
import pickle
import tempfile
import unittest
from pathlib import Path

from trustedge import detection
from trustedge.recover_baseline_if import (
    DEFAULT_IP,
    RecoveryError,
    apply_recovery,
    format_report,
    plan_recovery,
    reconstruct_baseline_if_bundle,
    rollback_recovery,
)
from trustedge.policy import SimulationPolicy
from trustedge.service import Gateway
from trustedge.simulation import fixture
from trustedge.storage import Storage

LAPTOP = DEFAULT_IP  # 172.20.0.10
CAMERA = '172.20.0.11'


class RecoverBaselineIfTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / 'recover.sqlite')
        self.store = Storage(self.path, 'simulation')
        self.g = Gateway(self.store, SimulationPolicy())
        self.g.register(LAPTOP, 'Studio laptop', device_type='laptop')
        self.g.register(CAMERA, 'Living room camera', device_type='iot-camera')
        for _ in range(50):
            self.g.window(LAPTOP, fixture(LAPTOP), 60)
            self.g.window(CAMERA, fixture(CAMERA), 60)
        # Corrupt laptop IF the way rolling refit did: replace blob with one
        # trained on detection-era fixture windows while keeping baseline vectors.
        d = self.store.devices()[LAPTOP]
        rollingish = []
        for _ in range(40):
            from trustedge.features import extract
            rollingish.append(extract(fixture(LAPTOP), 60))
        bad = detection.train_if(rollingish, d)
        bad['identity'] = (d['epoch'], d['generation'])
        detection.train_ae(bad, rollingish[:20])
        with self.store.transaction():
            self.store.save_model(LAPTOP, pickle.dumps(bad, protocol=5))
        self.corrupted_blob = self.store.model(LAPTOP)
        self.camera_blob = self.store.model(CAMERA)
        self.laptop_device_json = self.store.devices()[LAPTOP]
        self.camera_device_json = self.store.devices()[CAMERA]

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_reconstruct_omits_ae_and_keeps_identity(self):
        d = self.store.devices()[LAPTOP]
        bundle = reconstruct_baseline_if_bundle(d)
        self.assertEqual(bundle['identity'], (d['epoch'], d['generation']))
        self.assertNotIn('ae_model', bundle)
        self.assertNotIn('ae_scaler', bundle)
        self.assertNotIn('ae_threshold', bundle.get('calibration', {}))
        self.assertIn('model', bundle)
        self.assertIn('scaler', bundle)
        self.assertIn('calibration', bundle)
        detection.validate(bundle)

    def test_dry_run_plan_does_not_write(self):
        before_laptop = self.store.model(LAPTOP)
        before_camera = self.store.model(CAMERA)
        before_dev = {
            ip: self.store.devices()[ip]
            for ip in (LAPTOP, CAMERA)
        }
        plan = plan_recovery(self.store, LAPTOP)
        self.assertTrue(plan['blobs_differ'])
        self.assertFalse(plan['has_ae'])
        self.assertEqual(plan['identity'], (before_dev[LAPTOP]['epoch'], before_dev[LAPTOP]['generation']))
        s = plan['baseline_scores']
        self.assertEqual(s['n'], 50)
        self.assertIsNotNone(s['min'])
        self.assertEqual(self.store.model(LAPTOP), before_laptop)
        self.assertEqual(self.store.model(CAMERA), before_camera)
        self.assertEqual(self.store.devices()[LAPTOP], before_dev[LAPTOP])
        self.assertEqual(self.store.devices()[CAMERA], before_dev[CAMERA])
        report = format_report(plan, dry_run=True)
        self.assertIn('dry_run=True', report)
        self.assertIn('write=skipped', report)

    def test_apply_only_changes_laptop_model_payload(self):
        plan = plan_recovery(self.store, LAPTOP)
        gen_before = self.store.devices()[LAPTOP]['generation']
        tier_before = self.store.devices()[LAPTOP]['desired_tier']
        trust_before = self.store.devices()[LAPTOP]['trust']
        baseline_before = list(self.store.devices()[LAPTOP]['baseline'])
        applied = apply_recovery(self.store, plan)
        self.assertTrue(applied['device_json_unchanged'])
        self.assertTrue(applied['other_models_unchanged'])
        self.assertEqual(self.store.model(LAPTOP), plan['new_blob'])
        self.assertNotEqual(self.store.model(LAPTOP), self.corrupted_blob)
        self.assertEqual(self.store.model(CAMERA), self.camera_blob)
        d = self.store.devices()[LAPTOP]
        self.assertEqual(d['generation'], gen_before)
        self.assertEqual(d['desired_tier'], tier_before)
        self.assertEqual(d['trust'], trust_before)
        self.assertEqual(d['baseline'], baseline_before)
        self.assertEqual(self.store.devices()[CAMERA], self.camera_device_json)
        # Loaded bundle validates and matches identity.
        loaded = pickle.loads(self.store.model(LAPTOP))
        detection.validate(loaded)
        self.assertEqual(loaded['identity'], (d['epoch'], d['generation']))
        self.assertNotIn('ae_model', loaded)

    def test_rollback_restores_previous_blob(self):
        plan = plan_recovery(self.store, LAPTOP)
        apply_recovery(self.store, plan)
        self.assertEqual(self.store.model(LAPTOP), plan['new_blob'])
        rollback_recovery(self.store, plan)
        self.assertEqual(self.store.model(LAPTOP), self.corrupted_blob)
        self.assertEqual(self.store.model(CAMERA), self.camera_blob)
        self.assertEqual(self.store.devices()[LAPTOP]['baseline'], self.laptop_device_json['baseline'])
        self.assertEqual(self.store.devices()[LAPTOP]['generation'], self.laptop_device_json['generation'])

    def test_refuse_wrong_baseline_count(self):
        d = self.store.devices()[LAPTOP]
        d = dict(d)
        d['baseline'] = d['baseline'][:10]
        with self.assertRaises(RecoveryError):
            reconstruct_baseline_if_bundle(d)


if __name__ == '__main__':
    unittest.main()
