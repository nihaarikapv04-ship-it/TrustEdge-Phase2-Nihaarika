import tempfile
from pathlib import Path
import unittest
from trustedge.storage import Storage
from trustedge.policy import SimulationPolicy
from trustedge.service import Gateway
from trustedge.simulation import fixture
from trustedge.registry import new_device
from trustedge.trust import evaluate

IP='192.168.50.2'

class ScanResponseTests(unittest.TestCase):
    def test_one_scan_is_detected_but_does_not_immediately_quarantine(self):
        store=Storage(':memory:','simulation')
        try:
            g=Gateway(store,SimulationPolicy());g.register(IP,'camera')
            g.window(IP,fixture(IP,True),60)
            d=store.devices()[IP]
            self.assertEqual((d['trust'],d['anomaly_streak']),(.6,1))
            self.assertEqual((d['desired_tier'],d['applied_tier']),('CAUTIOUS','CAUTIOUS'))
            w=store.windows(IP)[0]
            self.assertTrue(w['hard'])
            self.assertEqual(w['reason'],'PORT_SCAN')
            self.assertEqual(w['score'],1.)
            g.window(IP,fixture(IP),60)
            self.assertEqual(store.devices()[IP]['anomaly_streak'],0)
            g.window(IP,fixture(IP,True),60)
            self.assertEqual(store.devices()[IP]['desired_tier'],'CAUTIOUS')
        finally:store.close()

    def test_scan_streak_survives_restart_and_only_third_scan_quarantines(self):
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'simulation.sqlite')
            store=Storage(path,'simulation')
            g=Gateway(store,SimulationPolicy());g.register(IP,'camera')
            for _ in range(2):g.window(IP,fixture(IP,True),60)
            self.assertEqual(store.devices()[IP]['desired_tier'],'CAUTIOUS')
            store.close()
            store=Storage(path,'simulation')
            try:
                g=Gateway(store,SimulationPolicy());g.reconcile()
                self.assertEqual(store.devices()[IP]['anomaly_streak'],2)
                g.window(IP,fixture(IP,True),60)
                self.assertEqual(store.devices()[IP]['applied_tier'],'QUARANTINE')
                self.assertEqual(store.devices()[IP]['trust'],.384)
            finally:store.close()

    def test_low_trust_does_not_skip_cautious_and_anomaly_cannot_grant_recovery(self):
        d=new_device(IP,'camera');d.update(learning=False,desired_tier='TRUSTED',trust=.2)
        for _ in range(3):evaluate(d,1,True)
        self.assertEqual(d['desired_tier'],'CAUTIOUS')
        d.update(trust=.99,normal_streak=9)
        evaluate(d,.6,False)
        self.assertEqual(d['desired_tier'],'CAUTIOUS')
        self.assertEqual(d['normal_streak'],0)
