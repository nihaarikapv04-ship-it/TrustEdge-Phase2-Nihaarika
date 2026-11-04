"""End-to-end Phase 1 behavioural parity through the unified Gateway pipeline.

Uses SimulationPolicy + fixture packets (not fabricated scores). Every trust/tier
value asserted below is read back from Gateway/Storage after process().
"""
import unittest

from trustedge.detection import BASELINE_WINDOWS, ANOMALY_THRESHOLD
from trustedge.features import Packet
from trustedge.policy import NftPolicy, SimulationPolicy
from trustedge.service import Gateway
from trustedge.simulation import fixture
from trustedge.storage import Storage
from trustedge.trust import DOWNGRADE_WINDOWS, HARD_RULE_TRUST, UPGRADE_WINDOWS

IP = '192.168.50.2'
DNS = '192.168.50.1'


def burst_anomaly(ip, n=200):
    """High-rate same-port burst: not a Phase 1 hard rule, but IF-anomalous after clean baseline."""
    return [Packet(ip, '192.0.2.10', 40, 'tcp', 443, False,
                   timestamp=i * 0.001, sport=20000 + (i % 50), tcp_flags='PA')
            for i in range(n)]


class Phase1PipelineParityTests(unittest.TestCase):
    def setUp(self):
        self.store = Storage(':memory:', 'simulation')
        self.g = Gateway(self.store, SimulationPolicy())
        self.g.reconcile()
        self.g.register(IP, 'camera', ['192.0.2.10'], 'iot-camera', 6)

    def tearDown(self):
        self.store.close()

    def _device(self):
        return self.store.devices()[IP]

    def test_baseline_is_phase1_fifty_windows(self):
        self.assertEqual(BASELINE_WINDOWS, 50)
        for i in range(BASELINE_WINDOWS):
            self.g.window(IP, fixture(IP, vary=True), 60)
            d = self._device()
            self.assertEqual(len(d['baseline']), min(i + 1, BASELINE_WINDOWS))
            if i + 1 < BASELINE_WINDOWS:
                self.assertTrue(d['learning'])
        d = self._device()
        self.assertFalse(d['learning'])
        self.assertIsNotNone(self.store.model(IP))
        self.assertTrue(d['model_info']['isolation_forest'])
        self.assertEqual(d['desired_tier'], 'CAUTIOUS')

    def test_if_ae_ewma_three_window_hard_rule_and_persistence(self):
        for _ in range(BASELINE_WINDOWS):
            self.g.window(IP, fixture(IP, vary=True), 60)
        self.assertFalse(self._device()['learning'])
        self.assertIsNotNone(self.store.model(IP))

        # Clean detection windows: train AE (needs 15 rolling normals) and reach TRUSTED.
        # Use stable normal fixtures after a varied baseline so scores stay below noise floor.
        for _ in range(max(UPGRADE_WINDOWS, 15)):
            self.g.window(IP, fixture(IP, vary=False), 60)
            w = self.store.windows(IP, 1)[0]
            self.assertFalse(w['hard'])
        d = self._device()
        # May take more than UPGRADE_WINDOWS if early post-baseline scores are elevated.
        guard = 0
        while d['desired_tier'] != 'TRUSTED' and guard < 40:
            self.g.window(IP, fixture(IP, vary=False), 60)
            d = self._device()
            guard += 1
        self.assertEqual(d['desired_tier'], 'TRUSTED')
        self.assertEqual(d['applied_tier'], 'TRUSTED')
        bundle_info = d['model_info']
        self.assertTrue(bundle_info['isolation_forest'])
        self.assertTrue(bundle_info.get('autoencoder'), 'AE must train on rolling normals')

        # Ordinary anomaly: three consecutive non-hard windows → one-tier downgrade.
        anomaly_rows = []
        for i in range(DOWNGRADE_WINDOWS):
            self.g.window(IP, burst_anomaly(IP), 60)
            w = self.store.windows(IP, 1)[0]
            d = self._device()
            anomaly_rows.append({
                'window': i + 1,
                'detection': 'anomalous' if (w['score'] or 0) >= ANOMALY_THRESHOLD else w['reason'],
                'score': w['score'],
                'hard': w['hard'],
                'trust': d['trust'],
                'tier': d['desired_tier'],
                'streak': d['anomaly_streak'],
            })
            self.assertFalse(w['hard'], 'ordinary path must not fire hard rules')
            self.assertGreaterEqual(w['score'], ANOMALY_THRESHOLD)
            if i < DOWNGRADE_WINDOWS - 1:
                self.assertEqual(d['desired_tier'], 'TRUSTED')
            else:
                self.assertEqual(d['desired_tier'], 'CAUTIOUS')

        # Publish table for the report (real Gateway values).
        self._anomaly_table = anomaly_rows
        print('\nTHREE_WINDOW_TABLE')
        print('| Window | Detection | Score | Trust | Tier | Streak |')
        print('|---|---|---|---|---|---|')
        for r in anomaly_rows:
            print(f"| Anomaly {r['window']} | {r['detection']} | {r['score']} | {r['trust']} | {r['tier']} | {r['streak']} |")

        # Single ordinary window must not jump TRUSTED → QUARANTINE.
        self.assertNotEqual(anomaly_rows[0]['tier'], 'QUARANTINE')

        # Hard-rule immediate quarantine remains separate.
        self.g.window(IP, fixture(IP, True), 60)
        d = self._device()
        w = self.store.windows(IP, 1)[0]
        self.assertTrue(w['hard'])
        self.assertEqual(d['trust'], HARD_RULE_TRUST)
        self.assertEqual(d['desired_tier'], 'QUARANTINE')

        # Clean windows cannot auto-release quarantine (intentional Phase 2 correction).
        for _ in range(UPGRADE_WINDOWS + 2):
            self.g.window(IP, fixture(IP, vary=False), 60)
        self.assertEqual(self._device()['desired_tier'], 'QUARANTINE')
        self.g.release(IP, 'operator reviewed clean after hard-rule event')
        self.assertEqual(self._device()['desired_tier'], 'CAUTIOUS')
        self.assertEqual(self._device()['trust'], 0.55)

    def test_dns_nft_matches_phase1_rates(self):
        policy = NftPolicy('eth1', '192.168.50.0/24', DNS, wan='eth0')
        cautious = policy.render({IP: {'desired_tier': 'CAUTIOUS', 'destinations': ['192.0.2.10']}})
        quarantine = policy.render({IP: {'desired_tier': 'QUARANTINE', 'destinations': []}})
        self.assertIn('udp dport 53 limit rate 10/minute accept', cautious)
        self.assertIn(f'ip saddr {IP} drop', cautious)
        forward = quarantine.split('chain forward', 1)[1]
        self.assertIn(f'ip saddr {IP} ip daddr {DNS} udp dport 53 accept', forward)
        self.assertNotIn(f'ip saddr {IP} ip daddr {DNS} udp dport 53 limit rate', forward)


if __name__ == '__main__':
    unittest.main()
