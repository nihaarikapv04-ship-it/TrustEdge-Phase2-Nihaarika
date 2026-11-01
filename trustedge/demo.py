"""Explicit offline dashboard demo. Creates a NEW simulation database only."""
import argparse
from dataclasses import replace
import os
from pathlib import Path
from .api import LocalServer
from .policy import SimulationPolicy
from .service import Gateway
from .simulation import fixture
from .storage import Storage


def seed_demo(gateway):
    if gateway.storage.devices():
        raise ValueError('demo seeding requires an empty simulation registry')
    mode = gateway.storage.db.execute("SELECT value FROM metadata WHERE key='mode'").fetchone()[0]
    if mode != 'simulation' or not isinstance(gateway.policy, SimulationPolicy):
        raise ValueError('demo requires simulation storage and policy')
    examples = [('192.168.50.10','Studio laptop','laptop',True),
                ('192.168.50.20','Living room camera','iot-camera',True),
                ('192.168.50.30','Office printer','printer',True),
                ('192.168.50.40','Hallway thermostat','iot-thermo',False),
                ('192.168.50.50','Guest device','custom',False)]
    for index,(ip,name,profile,trained) in enumerate(examples):
        gateway.register(ip,name,['192.0.2.10'],profile)
        packets = [replace(p,size=200+index*150) for p in fixture(ip)]
        for _ in range(65 if trained else 8):
            gateway.window(ip,packets,60)
        if index == 4:
            for _ in range(3):
                gateway.window(ip,fixture(ip,True),60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',required=True,help='new simulation database; existing paths are refused')
    parser.add_argument('--port',type=int,default=8080)
    args = parser.parse_args()
    token = os.environ.get('TRUSTEDGE_API_TOKEN','')
    if len(token) < 24:
        parser.error('set TRUSTEDGE_API_TOKEN to at least 24 characters')
    if Path(args.database).exists():
        parser.error('database already exists; choose a new path (no data will be overwritten)')
    os.umask(0o077)
    store = Storage(args.database,'simulation')
    gateway = Gateway(store,SimulationPolicy())
    server = None
    try:
        seed_demo(gateway)
        server = LocalServer(('127.0.0.1',args.port),gateway,token,'simulation')
        print(f'Explicit simulation dashboard: http://127.0.0.1:{args.port}',flush=True)
        print('Authenticate with your TRUSTEDGE_API_TOKEN. No capture or real enforcement is running.',flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if server:
            server.server_close()
        store.close()

if __name__ == '__main__':
    main()
