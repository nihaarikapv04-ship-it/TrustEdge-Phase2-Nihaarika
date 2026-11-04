"""Phase 1 dashboard compatibility API (/p1) over the Phase 2 gateway."""
import json
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from trustedge.api import LocalServer
from trustedge.service import Gateway
from trustedge.storage import Storage
from trustedge.policy import SimulationPolicy
from trustedge.simulation import fixture

TOKEN = 'phase1-compat-token-123456789012'
IP = '192.168.50.2'


class Phase1CompatTests(unittest.TestCase):
    def setUp(self):
        self.store = Storage(':memory:', 'simulation')
        self.g = Gateway(self.store, SimulationPolicy())
        self.g.reconcile()
        self.server = LocalServer(('127.0.0.1', 0), self.g, TOKEN, 'simulation')
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.store.close()

    def call(self, path, method='GET', body=None, auth=True):
        headers = {'Content-Type': 'application/json'}
        if auth:
            headers['Authorization'] = 'Bearer ' + TOKEN
        data = None if body is None else json.dumps(body).encode()
        req = Request(self.base + path, method=method, data=data, headers=headers)
        with urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read())

    def test_phase1_dashboard_asset_and_login_use_gateway_token(self):
        with urlopen(self.base + '/phase1', timeout=5) as response:
            html = response.read()
        self.assertIn(b'const API = \'/p1\'', html)
        self.assertIn(b'TrustEdge Dashboard (Phase 1 UI)', html)
        code, payload = self.call('/p1/auth/login', 'POST',
                                  {'username': 'admin', 'password': TOKEN}, auth=False)
        self.assertEqual(code, 200)
        self.assertEqual(payload['status'], 'ok')
        self.assertEqual(payload['data']['token'], TOKEN)

    def test_devices_status_history_and_hard_rule_quarantine_shape(self):
        code, payload = self.call('/p1/devices', 'POST',
                                  {'ip': IP, 'name': 'camera', 'type': 'iot-camera', 'dst': '192.0.2.10'})
        self.assertEqual(code, 201)
        self.assertEqual(payload['data']['tier'], 'CAUTIOUS')
        self.assertTrue(payload['data']['learning'])
        self.g.window(IP, fixture(IP, True), 60)
        code, payload = self.call('/p1/devices')
        self.assertEqual(payload['data'][0]['tier'], 'QUARANTINE')
        self.assertEqual(payload['data'][0]['trust_score'], 0.1)
        code, payload = self.call(f'/p1/devices/{IP}/history?n=10')
        self.assertEqual(payload['status'], 'ok')
        self.assertTrue(payload['data'])
        code, payload = self.call('/p1/events/anomalies?n=50')
        self.assertTrue(any(row.get('layer') == 'HARD_RULE' for row in payload['data']))
        code, payload = self.call(f'/p1/devices/{IP}/lift-quarantine', 'POST', {})
        self.assertEqual(payload['data']['tier'], 'CAUTIOUS')

    def test_phase2_console_still_served_at_root(self):
        with urlopen(self.base + '/', timeout=5) as response:
            html = response.read()
        self.assertIn(b'LOCAL SECURITY CONSOLE', html)
        self.assertNotIn(b'const API = \'/p1\'', html)
