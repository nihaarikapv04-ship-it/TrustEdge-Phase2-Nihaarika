"""Phase 1 dashboard compatibility API (/p1) over the Phase 2 gateway."""
import json
import os
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from trustedge.api import LocalServer
from trustedge.detection import BASELINE_WINDOWS
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
        from trustedge.phase1_compat import _attack_state, _stop_attack_runner
        for ip in list(_attack_state(self.server)):
            _stop_attack_runner(self.server, ip)
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.store.close()
        for key in ('TRUSTEDGE_ADMIN_PASSWORD', 'TRUSTEDGE_OPERATOR_PASSWORD',
                    'TRUSTEDGE_VIEWER_PASSWORD', 'TRUSTEDGE_JWT_SECRET'):
            os.environ.pop(key, None)

    def call(self, path, method='GET', body=None, token=None, timeout=30):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        data = None if body is None else json.dumps(body).encode()
        req = Request(self.base + path, method=method, data=data, headers=headers)
        with urlopen(req, timeout=timeout) as response:
            return response.status, json.loads(response.read())

    def login(self, username, password):
        code, payload = self.call('/p1/auth/login', 'POST',
                                  {'username': username, 'password': password})
        self.assertEqual(code, 200)
        self.assertEqual(payload['status'], 'ok')
        return payload['data']['token'], payload['data']['role']

    def test_phase1_dashboard_asset_and_jwt_login_roles(self):
        with urlopen(self.base + '/', timeout=5) as response:
            html = response.read()
        self.assertIn(b"const API = '/p1'", html)
        self.assertIn(b'TrustEdge Dashboard (Phase 1 UI)', html)
        with urlopen(self.base + '/phase1', timeout=5) as response:
            self.assertIn(b"const API = '/p1'", response.read())
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
        code, refreshed = self.call('/p1/auth/refresh', 'POST', {}, token=viewer_token)
        self.assertEqual(code, 200)
        self.assertEqual(refreshed['status'], 'ok')
        self.assertTrue(refreshed['data']['token'])
        self.assertEqual(refreshed['data']['role'], 'viewer')
        code, session = self.call('/p1/auth/session', token=viewer_token)
        self.assertEqual(code, 200)
        self.assertTrue(session['data']['authenticated'])
        self.assertEqual(session['data']['role'], 'viewer')
        with self.assertRaises(HTTPError) as denied_session:
            self.call('/p1/auth/session')
        self.assertEqual(denied_session.exception.code, 401)
        denied_session.exception.close()
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
        row = payload['data'][-1]
        self.assertIn('ts', row)
        self.assertIn('timestamp', row)
        self.assertEqual(row['ts'], row['timestamp'])
        self.assertIn('trust', row)
        self.assertEqual(row['trust'], row.get('trust_score'))
        code, payload = self.call('/p1/events/anomalies?n=50', token=token)
        self.assertTrue(any(row.get('layer') == 'hard_rule' for row in payload['data']))
        code, topo = self.call('/p1/topology', token=token)
        self.assertEqual(code, 200)
        self.assertIn('nodes', topo['data'])
        self.assertIn('edges', topo['data'])
        self.assertTrue(any(n.get('ip') == IP for n in topo['data']['nodes']))
        code, payload = self.call(f'/p1/devices/{IP}/lift-quarantine', 'POST', {}, token=token)
        self.assertEqual(payload['data']['tier'], 'CAUTIOUS')

    def test_attack_simulation_lifecycle_traffic_audit_and_network_load(self):
        token, _ = self.login('operator', OPERATOR_PASSWORD)
        code, payload = self.call('/p1/devices', 'POST',
                                  {'ip': IP, 'name': 'camera', 'type': 'iot-camera', 'dst': '192.0.2.10'},
                                  token=token)
        self.assertEqual(code, 201)
        code, types = self.call('/p1/attack-types', token=token)
        self.assertEqual(code, 200)
        names = {row['type'] for row in types['data']}
        self.assertTrue({'syn_flood', 'port_scan', 'icmp_flood'} <= names)

        # Attacks are blocked until 50 valid baseline windows complete.
        with self.assertRaises(HTTPError) as blocked:
            self.call(f'/p1/devices/{IP}/attack', 'POST', {'type': 'syn_flood'}, token=token)
        self.assertEqual(blocked.exception.code, 403)
        blocked.exception.close()
        code, learn = self.call('/p1/learning-status', token=token)
        self.assertEqual(code, 200)
        self.assertFalse(learn['data']['attacks_ready'])
        self.assertEqual(learn['data']['devices'][0]['baseline_windows'], 0)

        for _ in range(BASELINE_WINDOWS):
            self.g.window(IP, fixture(IP, vary=True), 60)
        code, learn = self.call('/p1/learning-status', token=token)
        self.assertTrue(learn['data']['attacks_ready'])
        self.assertEqual(learn['data']['status'], 'COMPLETE')
        self.assertFalse(self.g.storage.devices()[IP]['learning'])
        # Refresh / re-login must not clear completion metadata.
        started = learn['data']['learning_started_at']
        complete = learn['data']['baseline_complete_at']
        self.assertTrue(started and complete)
        code, learn2 = self.call('/p1/learning-status', token=token)
        self.assertEqual(learn2['data']['baseline_complete_at'], complete)

        # Start SYN flood via dashboard API — must quarantine through Gateway.window.
        code, payload = self.call(f'/p1/devices/{IP}/attack', 'POST',
                                  {'type': 'syn_flood'}, token=token)
        self.assertEqual(code, 200)
        self.assertTrue(payload['data']['is_attacking'])
        self.assertEqual(payload['data']['tier'], 'QUARANTINE')
        self.assertEqual(payload['data']['trust_score'], 0.1)

        # Duplicate start must be rejected.
        with self.assertRaises(HTTPError) as dup:
            self.call(f'/p1/devices/{IP}/attack', 'POST', {'type': 'port_scan'}, token=token)
        self.assertEqual(dup.exception.code, 409)
        dup.exception.close()

        # History / traffic / network-load reflect the injected window.
        code, hist = self.call(f'/p1/devices/{IP}/history?n=20', token=token)
        self.assertTrue(hist['data'])
        self.assertTrue(any(h.get('hard') for h in hist['data']))
        code, traffic = self.call('/p1/traffic?n=50', token=token)
        self.assertEqual(code, 200)
        syn_rows = [r for r in traffic['data'] if r.get('device') == IP]
        self.assertTrue(syn_rows)
        self.assertEqual(syn_rows[0].get('proto'), 'tcp')
        self.assertIsNotNone(syn_rows[0].get('sport'))
        self.assertIsNotNone(syn_rows[0].get('dport'))
        code, load = self.call('/p1/network-load?n=40', token=token)
        self.assertEqual(code, 200)
        self.assertEqual(load['data']['scope'], 'docker_lab')
        self.assertGreater(load['data']['total_packets'], 0)
        self.assertEqual(load['data']['host_nic'], 'unavailable')

        code, status = self.call('/p1/status')
        self.assertIn(IP, status['data'].get('attacks_running') or [])

        # Stop cleans runner state.
        code, payload = self.call(f'/p1/devices/{IP}/attack', 'DELETE', token=token)
        self.assertEqual(code, 200)
        self.assertFalse(payload['data']['is_attacking'])
        with self.assertRaises(HTTPError) as missing:
            self.call(f'/p1/devices/{IP}/attack', 'DELETE', token=token)
        self.assertEqual(missing.exception.code, 404)
        missing.exception.close()

        # ICMP attack: protocol set, ports null.
        self.call(f'/p1/devices/{IP}/lift-quarantine', 'POST', {}, token=token)
        code, payload = self.call(f'/p1/devices/{IP}/attack', 'POST',
                                  {'type': 'icmp_flood'}, token=token)
        self.assertEqual(code, 200)
        self.assertEqual(payload['data']['tier'], 'QUARANTINE')
        code, traffic = self.call('/p1/traffic?proto=1&n=50', token=token)
        icmp_rows = [r for r in traffic['data'] if r.get('device') == IP and r.get('proto') == 'icmp']
        self.assertTrue(icmp_rows)
        self.assertIsNone(icmp_rows[0].get('sport'))
        self.assertIsNone(icmp_rows[0].get('dport'))
        self.call(f'/p1/devices/{IP}/attack', 'DELETE', token=token)

        code, audit = self.call('/p1/audit-log?n=100', token=token)
        self.assertEqual(code, 200)
        actions = {row.get('action') for row in audit['data']}
        self.assertIn('START_ATTACK', actions)
        self.assertIn('STOP_ATTACK', actions)
        self.assertIn('TIER_CHANGED', actions)
        # No fabricated viewer identity on system events; actor preserved when present.
        start_rows = [r for r in audit['data'] if r.get('action') == 'START_ATTACK']
        self.assertTrue(start_rows)
        self.assertEqual(start_rows[0].get('username'), 'operator')

    def test_admin_user_management_and_phase2_console_fallback(self):
        admin_token, _ = self.login('admin', ADMIN_PASSWORD)
        code, payload = self.call('/p1/users', token=admin_token)
        self.assertGreaterEqual(len(payload['data']), 3)
        with urlopen(self.base + '/v2', timeout=5) as response:
            html = response.read()
        self.assertIn(b'LOCAL SECURITY CONSOLE', html)
        self.assertNotIn(b"const API = '/p1'", html)
