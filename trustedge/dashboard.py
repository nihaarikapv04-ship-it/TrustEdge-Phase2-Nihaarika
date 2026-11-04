"""Local dashboard projections. No outbound calls and no model deserialization."""
import os
from pathlib import Path
import shutil
import time
from .detection import BASELINE_WINDOWS
from .features import FEATURE_NAMES

STARTED = time.monotonic()


def host_health(database_path):
    memory = None
    try:
        values = {line.split(':')[0]: int(line.split()[1])*1024
                  for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemTotal:', 'MemAvailable:'))}
        memory = dict(total=values['MemTotal'], available=values['MemAvailable'])
    except (OSError, KeyError, ValueError):
        pass
    temperature = None
    try:
        temperature = int(Path('/sys/class/thermal/thermal_zone0/temp').read_text())/1000
    except (OSError, ValueError):
        pass
    disk = shutil.disk_usage(Path(database_path).resolve().parent)
    try:
        load_average = list(os.getloadavg())
    except OSError:
        load_average = None
    return dict(uptime_seconds=int(time.monotonic()-STARTED), cpu_count=os.cpu_count(),
                load_average=load_average, memory=memory, temperature_c=temperature,
                disk=dict(total=disk.total, free=disk.free))


def snapshot(server):
    g = server.gateway
    with g.lock:
        state = g.status()
        devices = []
        for device in state['devices']:
            # Do not send training vectors or serialized models to the browser.
            d = {k:v for k,v in device.items() if k not in ('baseline', 'rolling', 'signature_state', 'epoch')}
            signatures = device.get('signature_state', {})
            d.update(baseline_count=len(device['baseline']), baseline_required=BASELINE_WINDOWS,
                     rolling_count=len(device['rolling']), model_ready=g.storage.has_model(device['ip']),
                     signature_count=signatures.get('count',0), threshold=signatures.get('threshold',.7),
                     signature_complete=signatures.get('complete',False))
            devices.append(d)
        capture = server.collector
        capture_health = dict(running=capture.running, error=capture.error, dropped=capture.dropped) if capture else None
        ready = state['ready'] and (capture is None or (capture.running and not capture.error))
        return dict(ready=ready, error=state['error'], detection_errors=state['detection_errors'],
                    mode=server.mode, detector='Phase 1 · Isolation Forest + autoencoder',
                    capture=capture_health, devices=devices, events=g.storage.events(),
                    windows=g.storage.windows(limit=300), feature_names=list(FEATURE_NAMES),
                    health=host_health(g.storage.path), topology=getattr(server, 'topology', None),
                    retention=dict(windows_per_device=300, total_windows=10000, events=10000),
                    updated_at=time.time())


def main():
    """One-command simulation launcher; credentials never need manual copying."""
    import argparse
    import secrets
    import threading
    import webbrowser
    from .api import LocalServer
    from .demo import seed_demo
    from .policy import SimulationPolicy
    from .service import Gateway
    from .storage import Storage

    parser = argparse.ArgumentParser(description='Open the local simulation dashboard with automatic sign-in')
    parser.add_argument('--database', default='dashboard-local.sqlite')
    parser.add_argument('--port',type=int,default=8080)
    args = parser.parse_args()
    os.umask(0o077)
    store = Storage(args.database,'simulation')
    server = None
    worker = None
    try:
        gateway = Gateway(store,SimulationPolicy())
        if not store.devices():
            seed_demo(gateway)
        gateway.reconcile()
        token, code = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        server = LocalServer(('127.0.0.1',args.port),gateway,token,'simulation',pairing_code=code)
        worker = threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        url = f'http://127.0.0.1:{server.server_port}/#pair={code}'
        print('Opening the local simulation dashboard. Automatic sign-in is enabled.',flush=True)
        print('Keep this window open. Press Ctrl+C to stop. No hardware or real firewall is used.',flush=True)
        if not webbrowser.open(url):
            print('Browser could not open automatically. Open this single-use local link within two minutes:',flush=True)
            print(url,flush=True)
        while worker.is_alive():
            worker.join(timeout=.5)
    except KeyboardInterrupt:
        pass
    finally:
        if server:
            if worker and worker.is_alive():
                server.shutdown()
                worker.join(timeout=5)
            server.server_close()
        store.close()


if __name__ == '__main__':
    main()
