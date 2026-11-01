import json
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from trustedge.api import LocalServer
from trustedge.service import Gateway
from trustedge.storage import Storage
from trustedge.policy import PolicyError
from trustedge.simulation import fixture

IP='192.168.50.2'
TOKEN='dashboard-test-token-123456789'

class Policy:
    fail=False
    def apply(self,devices):
        if self.fail: raise PolicyError('nft rejected')

class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.store=Storage(':memory:','simulation')
        self.policy=Policy()
        self.g=Gateway(self.store,self.policy)
        self.g.reconcile()
        self.g.register(IP,'<img src=x onerror=alert(1)>',['192.0.2.10'])
        self.server=LocalServer(('127.0.0.1',0),self.g,TOKEN,'simulation')
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.base=f'http://127.0.0.1:{self.server.server_port}'
    def tearDown(self):
        self.server.shutdown();self.thread.join();self.server.server_close();self.store.close()
    def request(self,path,method='GET',body=None,auth=True):
        req=Request(self.base+path,method=method,data=json.dumps(body).encode() if body is not None else None,
                    headers={'Authorization':'Bearer '+TOKEN} if auth else {})
        with urlopen(req,timeout=5) as response:
            return response.headers,response.read()
    def value(self,path,**kwargs): return json.loads(self.request(path,**kwargs)[1])

    def test_static_assets_local_and_no_auth_data_leak(self):
        for path in ('/','/dashboard.css','/dashboard.js'):
            headers,data=self.request(path,auth=False)
            self.assertIn("default-src 'self'",headers['Content-Security-Policy'])
            self.assertNotIn(TOKEN.encode(),data)
            self.assertNotIn(b'cdn.',data)
        self.assertIn(b'textContent',self.request('/dashboard.js',auth=False)[1])
        for path in ('/dashboard',f'/devices/{IP}/history','/../storage.py'):
            with self.assertRaises(HTTPError) as result: self.request(path,auth=False)
            self.assertEqual(result.exception.code,401);result.exception.close()

    def test_projection_history_and_safe_data_contract(self):
        self.g.window(IP,fixture(IP),60)
        result=self.value('/dashboard')
        self.assertEqual(result['mode'],'simulation')
        device=result['devices'][0]
        self.assertNotIn('baseline',device)
        self.assertNotIn('rolling',device)
        self.assertNotIn('signature_state',device)
        self.assertNotIn('epoch',device)
        self.assertEqual(device['baseline_count'],1)
        history=self.value(f'/devices/{IP}/history?limit=10')
        self.assertEqual(len(history),1)
        self.assertEqual(len(history[0]['features']),14)
        self.assertEqual(history[0]['packets'],20)
        self.assertEqual(history[0]['bytes'],10000)
        self.assertEqual(history[0]['trust'],.75)
        self.assertTrue(result['ready'])
        self.assertEqual(result['capture'],None)

    def test_destination_update_failure_and_release_audit(self):
        self.policy.fail=True
        with self.assertRaises(HTTPError) as result:
            self.request(f'/devices/{IP}',method='PATCH',body={'name':'Updated camera','destinations':['192.0.2.11']})
        self.assertEqual(result.exception.code,503);result.exception.close()
        self.assertEqual(self.store.devices()[IP]['destinations'],['192.0.2.11'])
        self.assertFalse(self.g.status()['ready'])
        self.policy.fail=False;self.g.reconcile()
        for _ in range(3):
            self.g.window(IP,fixture(IP,True),60)
        with self.assertRaises(HTTPError) as result:
            self.request(f'/devices/{IP}/release',method='POST',body={'reason':'no'})
        self.assertEqual(result.exception.code,400);result.exception.close()
        self.request(f'/devices/{IP}/release',method='POST',body={'reason':'Verified firmware and reviewed detection'})
        d=self.store.devices()[IP]
        self.assertEqual((d['trust'],d['desired_tier'],d['applied_tier']),(.55,'CAUTIOUS','CAUTIOUS'))
        events=self.store.events()
        self.assertTrue(any(e['action']=='quarantine_release_requested' and 'reason' in e for e in events))
        self.assertTrue(any(e['action']=='tier_changed' and e['tier']=='CAUTIOUS' for e in events))
        self.assertTrue(any(e['action']=='registered' for e in events))

    def test_capture_failure_visible_and_no_simulation_controls_live(self):
        class Capture:
            running=False; error='capture stopped'; dropped=25
        self.server.collector=Capture()
        self.server.mode='live'
        result=self.value('/dashboard')
        self.assertFalse(result['ready'])
        self.assertEqual(result['capture']['dropped'],25)
        with self.assertRaises(HTTPError) as response:
            self.request(f'/devices/{IP}/simulate',method='POST',body={})
        self.assertEqual(response.exception.code,404);response.exception.close()

    def test_history_retention_deletion_and_rebaseline(self):
        with self.store.transaction():
            for i in range(310): self.store.record_window(IP,packets=i)
        self.assertEqual(len(self.store.windows(IP,1000)),300)
        self.assertEqual(self.store.windows(IP)[-1]['packets'],10)
        self.g.rebaseline(IP)
        self.assertEqual(len(self.store.windows(IP)),300)
        self.g.delete(IP)
        self.assertEqual(self.store.windows(),[])
        self.assertTrue(any(e['action']=='deleted' for e in self.store.events()))

    def test_release_failure_remains_pending_and_does_not_claim_applied(self):
        for _ in range(3):
            self.g.window(IP,fixture(IP,True),60)
        self.policy.fail=True
        with self.assertRaises(PolicyError): self.g.release(IP,'Reviewed device locally')
        d=self.store.devices()[IP]
        self.assertEqual((d['desired_tier'],d['applied_tier']),('CAUTIOUS','QUARANTINE'))
        self.assertFalse(self.value('/dashboard')['ready'])
        self.policy.fail=False
        self.g.reconcile()
        self.assertEqual(self.store.devices()[IP]['applied_tier'],'CAUTIOUS')

    def test_automatic_pairing_is_same_origin_expiring_and_single_use(self):
        import time
        code='single-use-pairing-secret'
        origin=self.base
        def pair(origin_header=origin, pairing_code=code):
            req=Request(self.base+'/session/pair',method='POST',
                        data=json.dumps({'code':pairing_code}).encode(),
                        headers={'Origin':origin_header,'Content-Type':'application/json'})
            with urlopen(req,timeout=5) as response:
                return json.loads(response.read())
        # Disabled by default, even on the existing simulation API.
        with self.assertRaises(HTTPError) as response: pair()
        self.assertEqual(response.exception.code,403);response.exception.close()
        self.server.pairing_code=code
        self.server.pairing_deadline=time.monotonic()+120
        with self.assertRaises(HTTPError) as response: pair('https://external.invalid')
        self.assertEqual(response.exception.code,403);response.exception.close()
        with self.assertRaises(HTTPError) as response: pair(pairing_code='wrong')
        self.assertEqual(response.exception.code,403);response.exception.close()
        self.assertEqual(pair()['token'],TOKEN)
        with self.assertRaises(HTTPError) as response: pair()
        self.assertEqual(response.exception.code,403);response.exception.close()
        with self.assertRaises(HTTPError) as response: self.request('/dashboard',auth=False)
        self.assertEqual(response.exception.code,401);response.exception.close()
        self.server.pairing_code=code
        self.server.pairing_deadline=0
        with self.assertRaises(HTTPError) as response: pair()
        self.assertEqual(response.exception.code,403);response.exception.close()

    def test_pi_dashboard_uses_configured_hardware_and_no_model_blob_reads(self):
        from unittest.mock import patch
        class PiCapture:
            running=True; error=None; dropped=0
        self.server.mode='live'
        self.server.collector=PiCapture()
        self.server.topology={'lan':'enx001122334455','wan':'eth0',
                              'gateway':'192.168.50.1','subnet':'192.168.50.0/24'}
        # Dashboard polling must not deserialize or fetch large model blobs from SD storage.
        with patch.object(self.store,'model',side_effect=AssertionError('model blob fetched')):
            result=self.value('/dashboard')
        self.assertEqual(result['mode'],'live')
        self.assertEqual(result['topology']['lan'],'enx001122334455')
        self.assertEqual(result['topology']['gateway'],'192.168.50.1')
        self.assertTrue(result['capture']['running'])
        self.assertTrue(result['ready'])
        self.assertFalse(result['devices'][0]['model_ready'])
        self.server.collector.running=False
        result=self.value('/dashboard')
        self.assertFalse(result['ready'])
        self.assertFalse(result['capture']['running'])

    def test_live_gateway_cannot_enable_automatic_demo_pairing(self):
        with self.assertRaises(ValueError):
            LocalServer(('127.0.0.1',0),self.g,TOKEN,'live',pairing_code='not-allowed')
