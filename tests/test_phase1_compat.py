"""Phase 1 dashboard compatibility API (/p1) over the Phase 2 gateway."""
import json
import os
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from trustedge.api import LocalServer
from trustedge.phase1_auth import decode_token, jwt_secret
from trustedge.policy import SimulationPolicy
from trustedge.service import Gateway
from trustedge.simulation import fixture
from trustedge.storage import Storage

GATEWAY_TOKEN = 'phase1-compat-gateway-token-xyz'
ADMIN_PASSWORD = 'admin-pass-123456'
OPERATOR_PASSWORD = 'operator-pass-123'
VIEWER_PASSWORD = 'viewer-pass-12345'
IP = '192.168.50.2'


class Phase1CompatTests(unittest.TestCase):
    def setUp(self):
        os.environ['TRUSTEDGE_ADMIN_PASSWORD'] = ADMIN_PASSWORD
        os.environ['TRUSTEDGE_OPERATOR_PASSWORD'] = OPERATOR_PASSWORD
        os.environ['TRUSTEDGE_VIEWER_PASSWORD'] = VIEWER_PASSWORD
        os.environ.pop('TRUSTEDGE_JWT_SECRET', None)
        self.store = Storage(':memory:', 'simulation')
        self.g = Gateway(self.store, SimulationPolicy())
        self.g.reconcile()
        self.server = LocalServer(('127.0.0.1', 0), self.g, GATEWAY_TOKEN, 'simulation')
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.store.close()
        for key in ('TRUSTEDGE_ADMIN_PASSWORD', 'TRUSTEDGE_OPERATOR_PASSWORD',
                    'TRUSTEDGE_VIEWER_PASSWORD', 'TRUSTEDGE_JWT_SECRET'):
            os.environ.pop(key, None)

    def call(self, path, method='GET', body=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        data = None if body is None else json.dumps(body).encode()
        req = Request(self.base + path, method=method, data=data, headers=headers)
        with urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read())

    def login(self, username, password):
        code, payload = self.call('/p1/auth/login', 'POST',
                                  {'username': username, 'password': password})
        self.assertEqual(code, 200)
        self.assertEqual(payload['status'], 'ok')
        return payload['data']['token'], payload['data']['role']

    def test_phase1_dashboard_asset_and_jwt_login_roles(self):
        with urlopen(self.base + '/phase1', timeout=5) as response:
            html = response.read()
        self.assertIn(b"const API = '/p1'", html)
        self.assertIn(b'TrustEdge Dashboard (Phase 1 UI)', html)
        # Arbitrary username + gateway token must not work.
        with self.assertRaises(HTTPError) as denied:
            self.call('/p1/auth/login', 'POST',
                      {'username': 'anyone', 'password': GATEWAY_TOKEN})
        self.assertEqual(denied.exception.code, 401)
        denied.exception.close()
        token, role = self.login('admin', ADMIN_PASSWORD)
        self.assertEqual(role, 'admin')
        payload = decode_token(token, jwt_secret(GATEWAY_TOKEN))
        self.assertEqual(payload['sub'], 'admin')
        self.assertEqual(payload['role'], 'admin')
        viewer_token, viewer_role = self.login('viewer', VIEWER_PASSWORD)
        self.assertEqual(viewer_role, 'viewer')
        with self.assertRaises(HTTPError) as forbidden:
            self.call('/p1/devices', 'POST',
                      {'ip': IP, 'name': 'cam', 'type': 'iot-camera'}, token=viewer_token)
        self.assertEqual(forbidden.exception.code, 403)
        forbidden.exception.close()

    def test_devices_status_history_hard_rule_and_release(self):
        token, _ = self.login('operator', OPERATOR_PASSWORD)
        code, payload = self.call('/p1/devices', 'POST',
                                  {'ip': IP, 'name': 'camera', 'type': 'iot-camera', 'dst': '192.0.2.10'},
                                  token=token)
        self.assertEqual(code, 201)
        self.assertEqual(payload['data']['tier'], 'CAUTIOUS')
        self.g.window(IP, fixture(IP, True), 60)
        code, payload = self.call('/p1/devices', token=token)
        self.assertEqual(payload['data'][0]['tier'], 'QUARANTINE')
        self.assertEqual(payload['data'][0]['trust_score'], 0.1)
        code, payload = self.call(f'/p1/devices/{IP}/history?n=10', token=token)
        self.assertTrue(payload['data'])
        code, payload = self.call('/p1/events/anomalies?n=50', token=token)
        self.assertTrue(any(row.get('layer') == 'hard_rule' for row in payload['data']))
        code, topo = self.call('/p1/topology', token=token)
        self.assertEqual(code, 200)
        self.assertIn('nodes', topo['data'])
        self.assertIn('edges', topo['data'])
        self.assertTrue(any(n.get('ip') == IP for n in topo['data']['nodes']))
        code, payload = self.call(f'/p1/devices/{IP}/lift-quarantine', 'POST', {}, token=token)
        self.assertEqual(payload['data']['tier'], 'CAUTIOUS')

    def test_admin_user_management_and_phase2_console_fallback(self):
        admin_token, _ = self.login('admin', ADMIN_PASSWORD)
        code, payload = self.call('/p1/users', token=admin_token)
        self.assertGreaterEqual(len(payload['data']), 3)
        with urlopen(self.base + '/', timeout=5) as response:
            html = response.read()
        self.assertIn(b'LOCAL SECURITY CONSOLE', html)
        self.assertNotIn(b"const API = '/p1'", html)
