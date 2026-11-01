"""Real packet scenario, launched ONLY by test_nft_linux inside unshare --net.

The outer network namespace and its children are discarded on exit. No host
interfaces, routes, sysctls, or firewall tables are changed.
"""
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time

from trustedge.config import PiConfig
from trustedge.hardware import render
from trustedge.policy import NftPolicy, PolicyError
from trustedge.service import Gateway
from trustedge.storage import Storage

SERVER = '''import socket, threading, time

def tcp(port):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(('0.0.0.0',port)); s.listen()
    def client(c):
        try:
            while True:
                data=c.recv(1024)
                if not data: break
                c.sendall(data)
        finally: c.close()
    def loop():
        while True:
            c,a=s.accept(); threading.Thread(target=client,args=(c,),daemon=True).start()
    threading.Thread(target=loop,daemon=True).start()

def udp(port):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',port))
    def loop():
        while True:
            data,a=s.recvfrom(1024); s.sendto(data,a)
    threading.Thread(target=loop,daemon=True).start()
for port in (53,80,443,9999): tcp(port)
for port in (53,67): udp(port)
print('ready',flush=True)
while True: time.sleep(1)
'''
PROBE = '''import socket,sys
host,port,proto,source=sys.argv[1:]; port=int(port)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if proto=='udp' else socket.SOCK_STREAM)
s.settimeout(.8)
try:
    if source != '0': s.bind(('0.0.0.0',int(source)))
    s.connect((host,port)); s.send(b'probe')
    assert s.recv(100)==b'probe'
except (OSError,AssertionError): sys.exit(1)
finally: s.close()
'''
SESSION = '''import socket,sys
s=socket.create_connection(('192.0.2.10',443),2); s.settimeout(.8)
print('ready',flush=True)
for line in sys.stdin:
    try:
        s.sendall(b'probe'); result=s.recv(100)==b'probe'
    except OSError: result=False
    print('allowed' if result else 'blocked',flush=True)
'''

def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10, **kwargs)

def read_line(process):
    readable, _, _ = select.select([process.stdout], [], [], 5)
    if not readable:
        raise AssertionError('namespace helper timed out')
    line = process.stdout.readline().strip()
    if not line:
        raise AssertionError('namespace helper exited unexpectedly')
    return line


def main():
    # Refuse accidental direct execution against the development machine's network.
    parent = os.readlink(f'/proc/{os.getppid()}/ns/net') if sys.platform == 'linux' else None
    if (len(sys.argv) != 3 or sys.argv[1] != '--parent-netns' or
            sys.argv[2] != parent or os.readlink('/proc/self/ns/net') == parent):
        raise SystemExit('Run through the opt-in test_nft_linux wrapper in a fresh network namespace')
    processes = []
    store = None
    try:
        def namespace():
            p = subprocess.Popen(['unshare','--net','sleep','180'])
            processes.append(p)
            deadline = time.monotonic()+5
            while time.monotonic() < deadline:
                if p.poll() is not None:
                    raise AssertionError('cannot create child network namespace')
                if os.readlink(f'/proc/{p.pid}/ns/net') != os.readlink('/proc/self/ns/net'):
                    return p.pid
                time.sleep(.02)
            raise AssertionError('namespace creation timed out')
        client, wan = namespace(), namespace()
        def inside(pid, args):
            return ['nsenter','--target',str(pid),'--net'] + args
        for local, remote, pid in [('lan0','client0',client), ('wan0','server0',wan)]:
            run(['ip','link','add',local,'type','veth','peer','name',remote])
            run(['ip','link','set',remote,'netns',str(pid)])
            run(['ip','link','set',local,'up'])
            run(inside(pid,['ip','link','set',remote,'up']))
            run(inside(pid,['ip','link','set','lo','up']))
        run(['ip','address','add','192.168.50.1/24','dev','lan0'])
        run(['ip','address','add','192.0.2.1/24','dev','wan0'])
        run(inside(client,['ip','address','add','192.168.50.2/24','dev','client0']))
        run(inside(client,['ip','route','add','default','via','192.168.50.1']))
        for ip in ('192.0.2.10/24','192.0.2.11/24'):
            run(inside(wan,['ip','address','add',ip,'dev','server0']))
        # No return route on WAN: successful replies exercise masquerading too.
        config = PiConfig(lan='lan0', wan='wan0')
        files = render(config)
        run(['nft','-f','-'], input=files['bootstrap.nft'])
        run(['nft','-f','-'], input=files['nat.nft'])
        run(['sysctl','-w','net.ipv4.ip_forward=1'])
        for prefix in ([], inside(wan, [])):
            p = subprocess.Popen(prefix+[sys.executable,'-u','-c',SERVER], stdout=subprocess.PIPE, text=True)
            processes.append(p)
            assert read_line(p) == 'ready'
        def probe(host, port, expected, proto='tcp', source=0):
            p = subprocess.run(inside(client,[sys.executable,'-c',PROBE,host,str(port),proto,str(source)]),
                               capture_output=True, text=True, timeout=5)
            assert (p.returncode == 0) == expected, (host,port,proto,expected,p.stderr)
        # Bootstrap denies even with forwarding enabled, but local DHCP/DNS works.
        probe('192.0.2.10',443,False)
        probe('192.168.50.1',53,True,'udp')
        probe('192.168.50.1',67,True,'udp',68)
        probe('192.168.50.1',9999,False)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory)/'state.sqlite')
            store = Storage(path,'live')
            policy = NftPolicy('lan0',config.subnet,config.gateway,wan='wan0')
            gateway = Gateway(store,policy)
            gateway.reconcile()
            gateway.register('192.168.50.2','camera',['192.0.2.10'])
            probe('192.0.2.10',443,True)
            probe('192.0.2.11',443,False)
            probe('192.0.2.10',9999,False)
            def tier(value):
                d = store.devices()['192.168.50.2']
                d['desired_tier'] = value
                with store.transaction(): store.save(d)
                gateway.reconcile()
            tier('TRUSTED')
            probe('192.0.2.11',9999,True)
            session = subprocess.Popen(inside(client,[sys.executable,'-u','-c',SESSION]),
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            processes.append(session)
            assert read_line(session) == 'ready'
            session.stdin.write('send\n'); session.stdin.flush()
            assert read_line(session) == 'allowed'
            # A rejected real nft transaction leaves the established connection permitted.
            original_runner = policy.runner
            def reject(args, **kwargs):
                kwargs['input'] += 'add rule inet nonexistent forward drop\n'
                return original_runner(args, **kwargs)
            policy.runner = reject
            try:
                tier('QUARANTINE')
            except PolicyError:
                pass
            else:
                raise AssertionError('invalid nft batch unexpectedly succeeded')
            assert store.devices()['192.168.50.2']['applied_tier'] == 'TRUSTED'
            session.stdin.write('send\n'); session.stdin.flush()
            assert read_line(session) == 'allowed'
            # Restart recovers durable quarantine and blocks that existing TCP flow.
            store.close()
            store = Storage(path,'live')
            policy = NftPolicy('lan0',config.subnet,config.gateway,wan='wan0')
            gateway = Gateway(store,policy)
            gateway.reconcile()
            session.stdin.write('send\n'); session.stdin.flush()
            assert read_line(session) == 'blocked'
            probe('192.0.2.10',443,False)
            probe('192.168.50.1',53,True)
            probe('192.168.50.1',67,True,'udp',68)
            gateway.delete('192.168.50.2')
            probe('192.0.2.10',443,False)
            assert not store.devices()
            # Emulate a cold boot: bootstrap table, then durable restart reconciliation.
            run(['nft','-f','-'],input=files['bootstrap.nft'])
            probe('192.0.2.10',443,False)
            gateway.reconcile()
            probe('192.0.2.10',443,False)
        print('Pi packet scenario passed: bootstrap, NAT, tiers, DNS/DHCP, rollback, restart, deletion')
    finally:
        if store:
            store.close()
        for p in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try: p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill(); p.wait()

if __name__ == '__main__':
    main()
