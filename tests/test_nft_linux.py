"""Opt-in real kernel tests in a disposable network namespace, never host rules."""
import os
import subprocess
import sys
import unittest
from trustedge.policy import NftPolicy

@unittest.skipUnless(sys.platform == 'linux' and os.environ.get('TRUSTEDGE_NFT_TESTS') == '1',
                     'requires Linux root, nft, unshare and TRUSTEDGE_NFT_TESTS=1')
class KernelPolicyTests(unittest.TestCase):
    def test_repeated_atomic_replacement_and_failed_transaction_preserves_rules(self):
        policy = NftPolicy('eth1', '192.168.50.0/24', '192.168.50.1')
        trusted = {'192.168.50.2': {'desired_tier': 'TRUSTED', 'destinations': []}}
        quarantine = {'192.168.50.2': {'desired_tier': 'QUARANTINE', 'destinations': []}}
        # All nft operations execute in this child's fresh namespace.
        script = '''import json, subprocess, sys
batches=json.load(sys.stdin)
def run(text):
    return subprocess.run(['nft','-f','-'],input=text,text=True,capture_output=True)
for batch in batches:
    result=run(batch)
    assert result.returncode == 0, result.stderr
before=subprocess.check_output(['nft','-s','list','ruleset'])
result=run('delete table inet trustedge\\nadd rule inet missing forward drop\\n')
assert result.returncode != 0
after=subprocess.check_output(['nft','-s','list','ruleset'])
assert before == after, 'failed transaction changed installed policy'
'''
        import json
        result = subprocess.run(['unshare', '--net', sys.executable, '-c', script],
                                input=json.dumps([policy.render({}), policy.render(trusted),
                                                  policy.render(quarantine), policy.render({})]),
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_pi_gateway_packet_path(self):
        from pathlib import Path
        script = Path(__file__).with_name('pi_network_scenario.py')
        result = subprocess.run(['unshare', '--net', sys.executable, str(script),
                                 '--parent-netns', os.readlink('/proc/self/ns/net')],
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
