"""Phase A local-first hardening: no cloud telemetry, SQLite persistence, enforcement audit."""
import json
import tempfile
import unittest
from pathlib import Path

from trustedge.api import LocalServer
from trustedge.phase1_compat import _device_is_stale, device_view, handle
from trustedge.policy import SimulationPolicy
from trustedge.registry import new_device
from trustedge.service import Gateway
from trustedge.storage import SCHEMA_VERSION, Storage


class TelemetryDisabledTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / 'lab.sqlite'
        self.storage = Storage(str(self.db), 'simulation')
        self.gateway = Gateway(self.storage, SimulationPolicy())
        self.server = LocalServer(('127.0.0.1', 0), self.gateway, 't' * 24, 'simulation')
        from trustedge import phase1_auth
        secret = phase1_auth.jwt_secret(self.server.token)
        self.token = phase1_auth.make_token('admin', 'admin', secret)

    def tearDown(self):
        self.server.server_close()
        self.storage.close()
        self.tmp.cleanup()

    def test_cloud_endpoints_disabled(self):
        code, payload = handle(self.server, 'GET', '/cloud/summary', {}, {}, self.token)
        self.assertEqual(code, 200)
        self.assertEqual(payload['status'], 'ok')
        data = payload['data']
        self.assertFalse(data.get('enabled', True))
        blob = (data.get('message', '') + ' ' + payload.get('message', '')).lower()
        self.assertTrue('local-only' in blob or 'disabled' in blob)

        code, payload = handle(self.server, 'GET', '/cloud/alerts', {}, {}, self.token)
        self.assertEqual(code, 200)
        self.assertEqual(payload['data'], [])

    def test_status_reports_cloud_disabled_and_db_health(self):
        code, payload = handle(self.server, 'GET', '/status', {}, {}, None)
        self.assertEqual(code, 200)
        data = payload['data']
        self.assertIs(data['cloud_api_ok'], False)
        self.assertEqual(data.get('cloud_telemetry'), 'disabled')
        self.assertEqual(data['database']['schema_version'], str(SCHEMA_VERSION))
        self.assertEqual(data['database']['integrity'], 'ok')
        self.assertIn('health', data)
        self.assertIn('firewall', data)

    def test_phase1_html_has_no_cdn_or_google_fonts(self):
        html = Path('trustedge/static/phase1.html').read_text(encoding='utf-8')
        self.assertNotIn('cdn.jsdelivr.net', html)
        self.assertNotIn('fonts.googleapis.com', html)
        self.assertNotIn('fonts.gstatic.com', html)
        self.assertIn('/vendor/chart.umd.min.js', html)
        vendor = Path('trustedge/static/vendor/chart.umd.min.js')
        self.assertTrue(vendor.exists())
        self.assertGreater(vendor.stat().st_size, 10_000)


class StorageMigrationTests(unittest.TestCase):
    def test_schema_v2_tables_and_persistence_across_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'a.sqlite')
            store = Storage(path, 'simulation')
            self.assertEqual(store.get_meta('schema_version'), str(SCHEMA_VERSION))
            device = new_device('192.168.50.10', 'cam', ['192.168.50.1'], 'iot-camera')
            with store.transaction():
                store.save(device)
                store.record_window('192.168.50.10', trust=0.9, score=0.1, reason='ok')
                store.event(action='tier_changed', ip='192.168.50.10', previous='CAUTIOUS',
                            tier='TRUSTED', trust=0.9)
                store.record_enforcement(
                    action='tier_changed', result='ok', ip='192.168.50.10',
                    desired_tier='TRUSTED', applied_tier='TRUSTED', rule_id='inet trustedge')
                store.record_health('firewall', 'ok', {'verified': True})
            # Checkpoint outside the writer transaction (PASSIVE still needs a quiet DB).
            store.checkpoint('PASSIVE')
            counts = store.counts()
            self.assertEqual(counts['devices'], 1)
            self.assertEqual(counts['windows'], 1)
            self.assertGreaterEqual(counts['enforcement'], 1)
            store.close()

            again = Storage(path, 'simulation')
            self.assertEqual(again.get_meta('schema_version'), str(SCHEMA_VERSION))
            self.assertEqual(again.counts()['devices'], 1)
            self.assertEqual(again.enforcement(ip='192.168.50.10')[0]['result'], 'ok')
            self.assertEqual(again.integrity_check(), 'ok')
            events = again.events(actions=('tier_changed',), limit=10)
            self.assertEqual(events[0]['action'], 'tier_changed')
            again.close()


class DeviceViewStaleTests(unittest.TestCase):
    def test_stale_when_last_seen_missing_after_learning(self):
        d = new_device('192.168.50.11', 'phone', device_type='smartphone')
        d['learning'] = False
        self.assertTrue(_device_is_stale(d, None, 5))
        view = device_view(d)
        self.assertTrue(view['stale'])
        self.assertEqual(view['enrollment_status'], 'enrolled')

    def test_not_stale_while_learning(self):
        d = new_device('192.168.50.12', 'laptop', device_type='laptop')
        self.assertTrue(d['learning'])
        self.assertFalse(_device_is_stale(d, None, 5))


class EnforcementAndRestartTests(unittest.TestCase):
    def test_reconcile_records_enforcement_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'b.sqlite')
            store = Storage(path, 'simulation')
            g = Gateway(store, SimulationPolicy())
            ip = g.register('192.168.50.20', 'printer', ['192.168.50.1'], 'printer')
            d = store.devices()[ip]
            self.assertEqual(d['applied_tier'], 'CAUTIOUS')
            # Force a desired change and reconcile.
            d['desired_tier'] = 'TRUSTED'
            with store.transaction():
                store.save(d)
            g.reconcile()
            d2 = store.devices()[ip]
            self.assertEqual(d2['applied_tier'], 'TRUSTED')
            self.assertEqual(d2['previous_tier'], 'CAUTIOUS')
            self.assertTrue(d2.get('tier_changed_at'))
            rows = store.enforcement(ip=ip)
            self.assertTrue(any(r['action'] == 'tier_changed' and r['result'] == 'ok' for r in rows))
            store.close()

            store2 = Storage(path, 'simulation')
            g2 = Gateway(store2, SimulationPolicy())
            restored = store2.devices()[ip]
            self.assertEqual(restored['applied_tier'], 'TRUSTED')
            self.assertEqual(restored['previous_tier'], 'CAUTIOUS')
            # ready becomes True after a successful reconcile (same as process restart).
            g2.reconcile()
            self.assertTrue(g2.status()['ready'])
            store2.close()


class AuditLogFilterTests(unittest.TestCase):
    def test_audit_log_not_dominated_by_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'c.sqlite')
            store = Storage(path, 'simulation')
            g = Gateway(store, SimulationPolicy())
            server = LocalServer(('127.0.0.1', 0), g, 't' * 24, 'simulation')
            ip = g.register('192.168.50.30', 'thermo', ['192.168.50.1'], 'iot-thermo')
            with store.transaction():
                for _ in range(50):
                    store.event(action='window', ip=ip, score=0.1, reason='ok')
                store.event(action='tier_changed', ip=ip, previous='CAUTIOUS', tier='TRUSTED', trust=0.9)
            # Authenticate as admin via minted token.
            from trustedge import phase1_auth
            secret = phase1_auth.jwt_secret(server.token)
            token = phase1_auth.make_token('admin', 'admin', secret)
            code, payload = handle(server, 'GET', '/audit-log', {'n': ['20']}, {}, token)
            self.assertEqual(code, 200)
            actions = [row['raw_action'] for row in payload['data']]
            self.assertIn('tier_changed', actions)
            self.assertNotIn('window', actions)
            server.server_close()
            store.close()


if __name__ == '__main__':
    unittest.main()
