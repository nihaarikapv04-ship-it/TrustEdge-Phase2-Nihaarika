import unittest
import numpy as np
from numpy.testing import assert_allclose
from trustedge.signatures import new_state, observe
from trustedge.trust import evaluate
from trustedge.registry import new_device
from trustedge.service import Gateway
from trustedge.policy import SimulationPolicy
from trustedge.storage import Storage

class SignatureTests(unittest.TestCase):
    def test_phase1_milestones_and_validation_vectors(self):
        state = new_state()
        vectors = []
        for i in range(30):
            vector = (np.arange(14)+i*.5).tolist()
            vectors.append(vector)
            probes = []
            complete = observe(state, vector, lambda values: probes.append(values) or .8)
            if i+1 in (10,20,30):
                mean = np.mean(vectors,axis=0)
                std = np.std(vectors,axis=0)+1e-6
                for probe,scale in zip(probes,(2.,5.,15.)):
                    assert_allclose(probe,np.maximum(mean+scale*std,0),atol=1e-12)
            self.assertEqual(complete, i == 29)
        self.assertEqual((state['threshold'],state['milestone'],state['count']),(.5,3,30))
        self.assertTrue(observe(state, [0]*14, lambda _: self.fail('completed state should not validate again')))
        self.assertEqual(state['count'],30)

    def test_failed_validation_defers_threshold_and_retries(self):
        state = new_state()
        for _ in range(10):
            observe(state,[1]*14,lambda _:0)
        self.assertEqual(state['threshold'],.7)
        observe(state,[1]*14,lambda _:.8)
        self.assertEqual(state['threshold'],.65)
        self.assertEqual(state['count'],11)

    def test_recovery_gate_and_phase1_immediate_hard_rule_quarantine(self):
        d = new_device('192.168.50.2','camera')
        d['learning'] = False
        for _ in range(9):
            evaluate(d,0,False)
            self.assertEqual(d['desired_tier'],'CAUTIOUS')
        evaluate(d,0,False)
        self.assertEqual(d['desired_tier'],'TRUSTED')
        evaluate(d,1,True)
        self.assertEqual(d['desired_tier'],'QUARANTINE')
        self.assertEqual(d['trust'],.1)

    def test_signature_state_and_streaks_survive_service_restart_and_reset(self):
        store=Storage(':memory:','simulation')
        try:
            g=Gateway(store,SimulationPolicy())
            ip=g.register('192.168.50.2','camera')
            d=store.devices()[ip]
            for _ in range(10): observe(d['signature_state'],[1]*14,lambda _:.8)
            d['anomaly_streak']=2
            with store.transaction(): store.save(d)
            g=Gateway(store,SimulationPolicy())
            self.assertEqual(store.devices()[ip],d)
            g.rebaseline(ip)
            state=store.devices()[ip]
            self.assertEqual(state['signature_state'],new_state())
            self.assertEqual(state['anomaly_streak'],0)
        finally: store.close()
