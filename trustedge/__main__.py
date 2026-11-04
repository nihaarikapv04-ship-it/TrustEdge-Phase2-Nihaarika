import argparse
import os
import threading
from .storage import Storage
from .policy import NftPolicy, SimulationPolicy, PolicyError
from .service import Gateway
from .collection import LiveCollector
from .api import LocalServer

def main():
    parser = argparse.ArgumentParser(description='Local TrustEdge gateway')
    parser.add_argument('--config', help='validated Pi gateway JSON; implies live mode')
    parser.add_argument('--mode', choices=['live', 'simulation'])
    parser.add_argument('--database')
    parser.add_argument('--lan')
    parser.add_argument('--wan')
    parser.add_argument('--subnet')
    parser.add_argument('--dns')
    parser.add_argument('--port', type=int, default=None)
    parser.add_argument('--bind', default=None,
                        help='127.0.0.1 (default) or 0.0.0.0 for Docker lab only')
    args = parser.parse_args()
    topology = None
    if args.config:
        if any((args.mode, args.database, args.lan, args.wan, args.subnet, args.dns, args.port, args.bind)):
            parser.error('--config cannot be combined with network/mode/database/port/bind overrides')
        from .config import PiConfig
        config = PiConfig.load(args.config)
        args.mode, args.database = 'live', config.database
        args.lan, args.wan, args.subnet, args.dns = config.lan, config.wan, config.subnet, config.gateway
        args.port = config.api_port
        topology = dict(lan=config.lan, wan=config.wan, gateway=config.gateway, subnet=config.subnet)
    if not args.mode or not args.database:
        parser.error('provide --config, or both --mode and --database')
    args.port = args.port or 8080
    bind = args.bind or os.environ.get('TRUSTEDGE_BIND', '127.0.0.1')
    lab_bind = os.environ.get('TRUSTEDGE_LAB_BIND', '') == '1'
    if bind not in ('127.0.0.1', '0.0.0.0'):
        parser.error('--bind must be 127.0.0.1 or 0.0.0.0')
    if bind != '127.0.0.1' and not lab_bind:
        parser.error('non-loopback bind requires TRUSTEDGE_LAB_BIND=1 (Docker lab only)')
    token = os.environ.get('TRUSTEDGE_API_TOKEN', '')
    if len(token) < 24:
        parser.error('set TRUSTEDGE_API_TOKEN to at least 24 characters')
    if args.mode == 'live' and not all((args.lan, args.subnet, args.dns)):
        parser.error('live mode requires --lan, --subnet and --dns')
    # Restrict newly created database/WAL files to the service account.
    os.umask(0o077)
    policy = (NftPolicy(args.lan, args.subnet, args.dns, wan=args.wan, api_port=args.port)
              if args.mode == 'live' else SimulationPolicy())
    storage = Storage(args.database, args.mode)
    gateway = Gateway(storage, policy)
    # Never begin capture or expose a ready service until startup policy is installed.
    gateway.reconcile()
    # Phase 1 default is 60s windows. Lab may set TRUSTEDGE_WINDOW_SECONDS to accelerate
    # real packet-capture baseline collection without fabricating feature vectors.
    window_seconds = 60
    raw_window = os.environ.get('TRUSTEDGE_WINDOW_SECONDS', '').strip()
    if raw_window:
        try:
            window_seconds = int(raw_window)
        except ValueError:
            parser.error('TRUSTEDGE_WINDOW_SECONDS must be an integer')
        if not 1 <= window_seconds <= 600:
            parser.error('TRUSTEDGE_WINDOW_SECONDS must be between 1 and 600')
        if not lab_bind and window_seconds != 60:
            parser.error('non-default TRUSTEDGE_WINDOW_SECONDS requires TRUSTEDGE_LAB_BIND=1')
    collector = (LiveCollector(gateway, args.lan, seconds=window_seconds)
                 if args.mode == 'live' else None)
    server = LocalServer((bind, args.port), gateway, token, args.mode, collector, topology,
                         allow_non_loopback=lab_bind)
    stop = threading.Event()
    def retry():
        while not stop.wait(5):
            try:
                gateway.reconcile()
            except PolicyError:
                pass
    reconciler = threading.Thread(target=retry, daemon=True)
    try:
        if collector:
            collector.start()
        reconciler.start()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        if collector:
            collector.stop()
        if reconciler.is_alive():
            reconciler.join(timeout=15)
        server.server_close()
        storage.close()

if __name__ == '__main__':
    main()
