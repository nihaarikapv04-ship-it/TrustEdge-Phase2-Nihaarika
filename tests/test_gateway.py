import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from trustedge.storage import Storage
from trustedge.service import Gateway
from trustedge.policy import NftPolicy, SimulationPolicy, PolicyError
from trustedge.simulation import fixture
from trustedge.api import LocalServer
from trustedge.collection import packet_metadata
from trustedge.detection import BASELINE_WINDOWS
from trustedge.trust import UPGRADE_WINDOWS

IP = '192.168.50.2'

class FakePolicy:
    def __init__(self):
        self.fail = False
        self.installed = {}
    def apply(self, devices):
        if self.fail:
            raise PolicyError('permission denied')
        self.installed = {ip:d['desired_tier'] for ip,d in devices.items()}

class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / 'state.sqlite')
        self.store = Storage(self.path, 'simulation')
        self.policy = FakePolicy()
        self.g = Gateway(self.store, self.policy)
        self.g.reconcile()
        self.g.register(IP, 'camera', ['192.0.2.10'])
    def tearDown(self):
        self.store.close()
        self.temp.cleanup()
    def quarantine(self):
        for _ in range(3):
            self.g.window(IP, fixture(IP, True), 60)

    def state(self):
        return self.store.devices()[IP]
    def restart(self):
        self.store.close()
        self.store = Storage(self.path, 'simulation')
        self.g = Gateway(self.store, self.policy)
        self.g.reconcile()

    def test_failed_quarantine_does_not_claim_success_and_recovers_after_restart(self):
        for _ in range(2):
            self.g.window(IP, fixture(IP, True), 60)
        self.policy.fail = True
        with self.assertRaises(PolicyError):
            self.g.window(IP, fixture(IP, True), 60)
        d = self.state()
        self.assertEqual(d['desired_tier'], 'QUARANTINE')
        self.assertEqual(d['applied_tier'], 'CAUTIOUS')
        self.assertFalse(self.g.status()['ready'])
        self.assertEqual(self.policy.installed[IP], 'CAUTIOUS')
        self.policy.fail = False
        self.restart()
        self.assertEqual(self.state()['applied_tier'], 'QUARANTINE')
        self.assertEqual(self.state()['trust'], .384)
        self.assertEqual(self.policy.installed[IP], 'QUARANTINE')

    def test_failed_deletion_is_retryable_and_not_resurrected(self):
        self.policy.fail = True
        with self.assertRaises(PolicyError):
            self.g.delete(IP)
        self.assertTrue(self.state()['deleting'])
        with self.assertRaises(KeyError):
            self.g.window(IP, fixture(IP), 60)
        self.policy.fail = False
        self.restart()
        self.assertNotIn(IP, self.store.devices())
        self.assertNotIn(IP, self.policy.installed)
        self.restart()
        self.assertNotIn(IP, self.store.devices())
        with self.assertRaises(KeyError):
            self.g.window(IP, fixture(IP), 60)

    def test_rebaseline_preserves_quarantine_across_restart(self):
        self.quarantine()
        self.g.rebaseline(IP)
        self.restart()
        d = self.state()
        self.assertEqual((d['trust'], d['desired_tier'], d['applied_tier']), (.384, 'QUARANTINE', 'QUARANTINE'))
        self.assertEqual(d['baseline'], [])
        self.assertEqual(d['generation'], 1)
        for _ in range(12):
            self.g.window(IP, fixture(IP), 60)
        self.assertEqual(self.state()['baseline'], [])
        self.assertEqual(self.state()['desired_tier'], 'QUARANTINE')

    def test_baseline_and_streak_survive_restart(self):
        for _ in range(BASELINE_WINDOWS):
            self.g.window(IP, fixture(IP), 60)
        before = self.state()
        self.restart()
        self.assertEqual(self.state(), before)
        self.assertFalse(self.state()['learning'])
        for _ in range(UPGRADE_WINDOWS):
            self.g.window(IP, fixture(IP), 60)
        self.assertEqual(self.state()['applied_tier'], 'TRUSTED')

    def test_rebaseline_failure_keeps_old_applied_and_new_intent(self):
        for _ in range(BASELINE_WINDOWS + UPGRADE_WINDOWS):
            self.g.window(IP, fixture(IP), 60)
        self.policy.fail = True
        with self.assertRaises(PolicyError):
            self.g.rebaseline(IP)
        self.assertEqual(self.state()['applied_tier'], 'TRUSTED')
        self.assertEqual(self.state()['desired_tier'], 'CAUTIOUS')
        self.policy.fail = False
        self.restart()
        self.assertEqual(self.state()['applied_tier'], 'CAUTIOUS')
        self.assertTrue(self.state()['learning'])

    def test_failed_initial_registration_is_recovered(self):
        self.policy.fail = True
        other = '192.168.50.3'
        with self.assertRaises(PolicyError):
            self.g.register(other, 'printer')
        self.assertIsNone(self.store.devices()[other]['applied_tier'])
        self.policy.fail = False
        self.restart()
        self.assertEqual(self.store.devices()[other]['applied_tier'], 'CAUTIOUS')

    def test_stale_capture_cannot_repopulate_rebaseline_or_reenrollment(self):
        old = self.state()
        identity = (old['epoch'], old['generation'])
        self.g.rebaseline(IP)
        self.g.window(IP, fixture(IP, True), 60, identity)
        self.assertEqual(self.state()['desired_tier'], 'CAUTIOUS')
        self.assertEqual(self.state()['baseline'], [])
        self.g.delete(IP)
        self.g.register(IP, 'replacement')
        self.g.window(IP, fixture(IP, True), 60, identity)
        self.assertEqual(self.state()['desired_tier'], 'CAUTIOUS')

    def test_live_cannot_use_simulation_database(self):
        with self.assertRaises(ValueError):
            Storage(self.path, 'live')

    def test_api_auth_and_policy_failure(self):
        server = LocalServer(('127.0.0.1', 0), self.g, 'a'*24, 'simulation')
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            with self.assertRaises(HTTPError) as error:
                urlopen(base + '/status', timeout=5)
            self.assertEqual(error.exception.code, 401)
            error.exception.close()
            self.policy.fail = True
            req = Request(base + f'/devices/{IP}', method='DELETE', headers={'Authorization': 'Bearer ' + 'a'*24})
            with self.assertRaises(HTTPError) as error:
                urlopen(req, timeout=5)
            self.assertEqual(error.exception.code, 503)
            error.exception.close()
            self.assertTrue(self.state()['deleting'])
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

class PolicyTests(unittest.TestCase):
    def test_nonzero_exit_and_os_error_and_timeout_are_failures(self):
        for outcome in (subprocess.CompletedProcess([], 1, '', 'rejected'), FileNotFoundError('nft'), subprocess.TimeoutExpired('nft', 10)):
            def runner(*args, **kwargs):
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome
            with self.subTest(outcome=outcome):
                with self.assertRaises(PolicyError):
                    NftPolicy('eth1', '192.168.50.0/24', '192.168.50.1', runner).apply({})

    def test_ordering_and_destination_constraints_and_atomic_batch(self):
        calls = []
        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args, 0, '', '')
        policy = NftPolicy('eth1', '192.168.50.0/24', '192.168.50.1', runner)
        policy.apply({IP: {'desired_tier': 'QUARANTINE', 'destinations': []}})
        self.assertEqual(len(calls), 1)
        args, options = calls[0]
        self.assertEqual(args, ['nft', '-f', '-'])
        script = options['input']
        self.assertTrue(script.startswith('add table inet trustedge\ndelete table inet trustedge\n'))
        self.assertIn('meta nfproto ipv6 drop', script)
        self.assertNotIn('ct state established,related accept', script)
        self.assertLess(script.index('udp dport 53'), script.index(f'ip saddr {IP} drop'))
        cautious = policy.render({IP: {'desired_tier': 'CAUTIOUS', 'destinations': ['192.0.2.10']}})
        self.assertIn('ip daddr 192.0.2.10 tcp dport { 80, 443 } limit rate', cautious)
        self.assertNotIn('flush ruleset', script)
        self.assertIn('iifname "eth1" drop', policy.render({}))

    def test_invalid_policy_inputs_rejected(self):
        with self.assertRaises(ValueError):
            NftPolicy('eth1;reboot', '192.168.50.0/24', '192.168.50.1')

    def test_capture_metadata_has_phase1_fields(self):
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP as IPv4, TCP
        raw = Ether(src='02:00:00:00:00:02', dst='02:00:00:00:00:01')/IPv4(src=IP, dst='192.0.2.10')/TCP(sport=1234, dport=443, flags='SA')
        packet = packet_metadata(raw)
        self.assertEqual((packet.src, packet.dst, packet.port, packet.syn, packet.sport),
                         (IP, '192.0.2.10', 443, True, 1234))
        self.assertEqual(packet.size, len(raw))
        self.assertIsNotNone(packet.timestamp)
        self.assertEqual(packet.tcp_flags, 'SA')
        self.assertIsNone(packet_metadata(Ether(src='02:00:00:00:00:02', dst='02:00:00:00:00:01')))

if __name__ == '__main__':
    unittest.main()
