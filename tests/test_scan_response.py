import tempfile
from pathlib import Path
import unittest
from trustedge.storage import Storage
from trustedge.policy import SimulationPolicy
from trustedge.service import Gateway
from trustedge.simulation import fixture
from trustedge.registry import new_device
from trustedge.trust import HARD_RULE_TRUST, evaluate

IP='192.168.50.2'

class ScanResponseTests(unittest.TestCase):
    def test_one_scan_immediately_quarantines_phase1_hard_rule(self):
        store=Storage(':memory:','simulation')
        try:
            g=Gateway(store,SimulationPolicy());g.register(IP,'camera')
            g.window(IP,fixture(IP,True),60)
            d=store.devices()[IP]
            self.assertEqual(d['trust'], HARD_RULE_TRUST)
            self.assertEqual((d['desired_tier'],d['applied_tier']),('QUARANTINE','QUARANTINE'))
            w=store.windows(IP)[0]
            self.assertTrue(w['hard'])
            self.assertEqual(w['reason'],'PORT_SCAN')
            self.assertEqual(w['score'],1.)
        finally:store.close()

    def test_hard_rule_quarantine_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'simulation.sqlite')
            store=Storage(path,'simulation')
            g=Gateway(store,SimulationPolicy());g.register(IP,'camera')
            g.window(IP,fixture(IP,True),60)
            self.assertEqual(store.devices()[IP]['desired_tier'],'QUARANTINE')
            store.close()
            store=Storage(path,'simulation')
            try:
                g=Gateway(store,SimulationPolicy());g.reconcile()
                self.assertEqual(store.devices()[IP]['applied_tier'],'QUARANTINE')
                self.assertEqual(store.devices()[IP]['trust'], HARD_RULE_TRUST)
            finally:store.close()

    def test_non_hard_low_trust_does_not_skip_cautious_and_anomaly_cannot_grant_recovery(self):
        d=new_device(IP,'camera');d.update(learning=False,desired_tier='TRUSTED',trust=.2)
        for _ in range(3):evaluate(d,1,False)
        self.assertEqual(d['desired_tier'],'CAUTIOUS')
        d.update(desired_tier='QUARANTINE',trust=.99,normal_streak=9)
        evaluate(d,0,False)
        self.assertEqual(d['desired_tier'],'QUARANTINE')
