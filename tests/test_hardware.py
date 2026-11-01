import json
import subprocess
import unittest
from unittest.mock import Mock
from trustedge.config import PiConfig
from trustedge.hardware import render, preflight
from trustedge.policy import NftPolicy, PolicyError
from trustedge.storage import Storage
from trustedge.service import Gateway

class PiConfigTests(unittest.TestCase):
    def test_defaults_produce_local_gateway_artifacts(self):
        config = PiConfig()
        files = render(config)
        self.assertEqual(config.subnet, '192.168.50.0/24')
        self.assertEqual(config.gateway, '192.168.50.1')
        self.assertIn('net.ipv4.ip_forward=0', files['90-trustedge.conf'])
        unit = files['trustedge-network.service']
        self.assertLess(unit.index('bootstrap.nft'), unit.index('nat.nft'))
        self.assertLess(unit.index('nat.nft'), unit.index('ip_forward=1'))
        self.assertIn('Requires=trustedge-network.service dnsmasq.service', files['trustedge.service'])
        self.assertIn('method=manual', files['trustedge-lan.nmconnection'])
        self.assertNotIn('method=shared', files['trustedge-lan.nmconnection'])
        self.assertIn('no-resolv', files['dnsmasq-trustedge.conf'])
        self.assertNotIn('server=', files['dnsmasq-trustedge.conf'])
        self.assertIn('dhcp-option=option:router,192.168.50.1', files['dnsmasq-trustedge.conf'])
        self.assertIn('oifname "eth0" masquerade', files['nat.nft'])
        self.assertNotIn('flush ruleset', ''.join(files.values()))
        self.assertNotIn('cloud', ''.join(files.values()).lower())

    def test_invalid_config_rejected(self):
        for changes in ({'lan':'eth0'}, {'wan':'eth0\nreboot'},
                        {'dhcp_start':'192.168.1.100'}, {'dhcp_start':'192.168.50.1'},
                        {'dhcp_end':'192.168.50.255'}, {'dns_upstream':['192.168.50.1']},
                        {'database':'/tmp/untrusted.sqlite'}, {'api_port':True},
                        {'reservations':[{'mac':'bad', 'ip':'192.168.50.2'}]},
                        {'reservations':[{'mac':'02:00:00:00:00:02', 'ip':'192.168.50.1'}]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                PiConfig(**changes)

    def test_reservations_dns_and_routed_mode(self):
        config = PiConfig(dns_upstream=['192.168.1.1'], masquerade=False,
                          reservations=[{'mac':'02:00:00:00:00:02', 'ip':'192.168.50.2'}])
        files = render(config)
        self.assertIn('server=192.168.1.1', files['dnsmasq-trustedge.conf'])
        self.assertIn('dhcp-host=02:00:00:00:00:02,192.168.50.2', files['dnsmasq-trustedge.conf'])
        self.assertNotIn('masquerade', files['nat.nft'])

    def test_enrollment_outside_lan_rejected_without_persisting_intent(self):
        store = Storage(':memory:', 'live')
        try:
            policy = NftPolicy('eth1', '192.168.50.0/24', '192.168.50.1', wan='eth0', runner=Mock())
            gateway = Gateway(store, policy)
            for ip in ('192.168.1.2', '192.168.50.0', '192.168.50.255', '192.168.50.1'):
                with self.subTest(ip=ip), self.assertRaises(ValueError):
                    gateway.register(ip, 'invalid')
            self.assertEqual(store.devices(), {})
            policy.runner.assert_not_called()
        finally:
            store.close()

    def test_live_policy_constrains_both_interfaces(self):
        policy = NftPolicy('eth1', '192.168.50.0/24', '192.168.50.1', wan='eth0')
        text = policy.render({'192.168.50.2': {'desired_tier':'TRUSTED'}})
        self.assertIn('iifname "eth1" oifname "eth0" ip saddr 192.168.50.2 accept', text)
        self.assertIn('iifname "eth0" oifname "eth1" ip daddr 192.168.50.2 ct state established,related accept', text)

class PreflightTests(unittest.TestCase):
    def runner(self, args, **kwargs):
        if args == ['ip','-j','link','show']:
            data = [{'ifname': n, 'flags':['UP']} for n in ('eth1','eth0')]
        elif 'address' in args:
            data = [{'ifname':'eth1','addr_info':[{'local':'192.168.50.1', 'prefixlen':24}]},
                    {'ifname':'eth0','addr_info':[{'local':'192.168.1.2','prefixlen':24}]}]
        elif 'route' in args:
            data = [{'dev':'eth0'}]
        else:
            return subprocess.CompletedProcess(args, 0, '1\n' if args[0] == 'sysctl' else '', '')
        return subprocess.CompletedProcess(args, 0, json.dumps(data), '')

    def test_success_is_read_only_and_no_network_probes(self):
        runner = Mock(side_effect=self.runner)
        self.assertEqual(preflight(PiConfig(), runner, system='Linux', which=lambda _:True), [])
        for call in runner.call_args_list:
            args = call.args[0]
            self.assertIn(args[0], ('ip','sysctl','nft'))
            self.assertNotIn('-w', args)
            if args[0] == 'nft':
                self.assertIn('--check', args)

    def test_non_linux_and_missing_packages(self):
        self.assertTrue(preflight(PiConfig(), system='Darwin'))
        self.assertIn('missing command: nft', preflight(PiConfig(), system='Linux', which=lambda _:False))

    def test_overlap_wrong_route_disabled_forwarding_and_failed_nft(self):
        def runner(args, **kwargs):
            result = self.runner(args, **kwargs)
            if 'address' in args:
                result.stdout = result.stdout.replace('192.168.1.2', '192.168.50.10')
            elif 'route' in args:
                result.stdout = '[]'
            elif args[0] == 'sysctl':
                result.stdout = '0'
            elif args[0] == 'nft':
                result.returncode, result.stderr = 1, 'permission denied'
            return result
        issues = preflight(PiConfig(), runner, system='Linux', which=lambda _:True)
        self.assertEqual(len(issues), 4)
        self.assertTrue(any('overlap' in issue for issue in issues))
