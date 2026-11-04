"""Phase 1 firewall/trust policy parity against reference ae8ecc7."""
import tempfile
import unittest
from pathlib import Path

from trustedge.registry import new_device
from trustedge.trust import HARD_RULE_TRUST, evaluate, next_trust, target_tier
from trustedge.storage import Storage
from trustedge.policy import SimulationPolicy
from trustedge.service import Gateway
from trustedge.simulation import fixture
from test_phase1_ml import reference

IP = '192.168.50.2'


class Phase1HardRuleParityTests(unittest.TestCase):
    def test_hard_rule_ewma_matches_phase1_before_override(self):
        with tempfile.TemporaryDirectory() as temp:
            ref = reference(temp)
            ref.trust_scores[IP] = 0.75
            expected = ref.update_trust(IP, 1.0, False, True)
            self.assertEqual(next_trust(0.75, 1.0, hard=True), expected)
            self.assertEqual(expected, round(0.2 * 0.75, 4))

    def test_hard_rule_forces_trust_0_1_and_immediate_quarantine(self):
        d = new_device(IP, 'camera')
        d.update(learning=False, desired_tier='TRUSTED', trust=0.99)
        evaluate(d, 1.0, True)
        self.assertEqual(d['trust'], HARD_RULE_TRUST)
        self.assertEqual(d['desired_tier'], 'QUARANTINE')
        self.assertEqual(d['anomaly_streak'], 0)
        self.assertEqual(target_tier(HARD_RULE_TRUST), 'QUARANTINE')

    def test_one_port_scan_window_quarantines_through_gateway(self):
        store = Storage(':memory:', 'simulation')
        try:
            g = Gateway(store, SimulationPolicy())
            g.register(IP, 'camera')
            g.window(IP, fixture(IP, True), 60)
            d = store.devices()[IP]
            self.assertTrue(store.windows(IP)[0]['hard'])
            self.assertEqual(store.windows(IP)[0]['reason'], 'PORT_SCAN')
            self.assertEqual(d['trust'], HARD_RULE_TRUST)
            self.assertEqual((d['desired_tier'], d['applied_tier']), ('QUARANTINE', 'QUARANTINE'))
        finally:
            store.close()

    def test_hard_rule_from_trusted_skips_cautious(self):
        d = new_device(IP, 'camera')
        d.update(learning=False, desired_tier='TRUSTED', trust=0.9)
        evaluate(d, 1.0, True)
        self.assertEqual(d['desired_tier'], 'QUARANTINE')


class Phase1TierEnrollmentRecoveryTests(unittest.TestCase):
    def test_enrollment_starts_cautious_while_learning(self):
        # Intentional correction vs Phase 1 TRUSTED enrollment — documented in POLICY_CORRECTIONS.md
        d = new_device(IP, 'camera')
        self.assertTrue(d['learning'])
        self.assertEqual(d['desired_tier'], 'CAUTIOUS')
        self.assertEqual(d['trust'], 0.75)

    def test_cautious_and_trusted_thresholds_match_phase1(self):
        self.assertEqual(target_tier(0.75), 'TRUSTED')
        self.assertEqual(target_tier(0.7499), 'CAUTIOUS')
        self.assertEqual(target_tier(0.40), 'CAUTIOUS')
        self.assertEqual(target_tier(0.3999), 'QUARANTINE')

    def test_non_hard_ml_downgrade_is_one_tier_per_streak(self):
        # Intentional correction vs Phase 1 jump-to-target
        d = new_device(IP, 'camera')
        d.update(learning=False, desired_tier='TRUSTED', trust=0.2)
        for _ in range(2):
            evaluate(d, 1.0, False)
            self.assertEqual(d['desired_tier'], 'TRUSTED')
        evaluate(d, 1.0, False)
        self.assertEqual(d['desired_tier'], 'CAUTIOUS')

    def test_quarantine_does_not_auto_recover_without_release(self):
        store = Storage(':memory:', 'simulation')
        try:
            g = Gateway(store, SimulationPolicy())
            g.register(IP, 'camera')
            g.window(IP, fixture(IP, True), 60)
            self.assertEqual(store.devices()[IP]['desired_tier'], 'QUARANTINE')
            for _ in range(12):
                g.window(IP, fixture(IP), 60)
            self.assertEqual(store.devices()[IP]['desired_tier'], 'QUARANTINE')
            g.release(IP, 'reviewed clean after hard-rule event')
            d = store.devices()[IP]
            self.assertEqual(d['desired_tier'], 'CAUTIOUS')
            self.assertEqual(d['trust'], 0.55)
        finally:
            store.close()

    def test_hard_rule_quarantine_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'simulation.sqlite')
            store = Storage(path, 'simulation')
            g = Gateway(store, SimulationPolicy())
            g.register(IP, 'camera')
            g.window(IP, fixture(IP, True), 60)
            store.close()
            store = Storage(path, 'simulation')
            try:
                g = Gateway(store, SimulationPolicy())
                g.reconcile()
                d = store.devices()[IP]
                self.assertEqual(d['trust'], HARD_RULE_TRUST)
                self.assertEqual(d['applied_tier'], 'QUARANTINE')
            finally:
                store.close()
