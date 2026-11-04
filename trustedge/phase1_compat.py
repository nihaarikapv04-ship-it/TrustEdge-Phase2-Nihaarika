"""Phase 1 dashboard API compatibility wrapper over the Phase 2 gateway.

Served under `/p1/*`. Cloud/RBAC/users remain stubbed; attack simulation maps to
fixture windows in simulation mode only. The Phase 2 console at `/` is unchanged.
"""
import hmac
import json
from urllib.parse import parse_qs, urlsplit

from .detection import BASELINE_WINDOWS, CONTAMINATION
from .policy import PolicyError
from .detection import DetectionError
from .simulation import fixture


def ok(data=None, msg='ok', code=200):
    body = {'status': 'ok', 'message': msg}
    if data is not None:
        body['data'] = data
    return code, body


def err(msg, code=400):
    return code, {'status': 'error', 'message': msg}


def device_view(device):
    signatures = device.get('signature_state') or {}
    destinations = device.get('destinations') or []
    return {
        'ip': device['ip'],
        'name': device['name'],
        'rate': device.get('rate', 5),
        'dst': destinations[0] if destinations else '172.21.0.10',
        'type': device.get('device_type', 'custom'),
        'trust_score': round(float(device.get('trust', 0)), 4),
        'tier': device.get('desired_tier'),
        'policy_tier': device.get('applied_tier') or device.get('desired_tier'),
        'learning': bool(device.get('learning')),
        'is_attacking': False,
        'baseline_windows': len(device.get('baseline') or []),
        'baseline_required': BASELINE_WINDOWS,
        'current_packets': 0,
        'anomaly_streak': device.get('anomaly_streak', 0),
        'normal_streak': device.get('normal_streak', 0),
        'signatures': signatures.get('count', 0),
        'threshold': signatures.get('threshold', .7),
        'sig_complete': signatures.get('complete', False),
        'last_seen': None,
        'stale': False,
        'desired_tier': device.get('desired_tier'),
        'applied_tier': device.get('applied_tier'),
    }


def history_rows(windows):
    rows = []
    for window in reversed(windows):
        rows.append({
            'timestamp': window.get('timestamp'),
            'trust': window.get('trust'),
            'anomaly': window.get('score'),
            'tier': window.get('desired_tier') or window.get('applied_tier'),
            'ae_suppressed': bool(window.get('ae_suppressed')),
            'hard': bool(window.get('hard')),
            'reason': window.get('reason'),
            'packets': window.get('packets'),
        })
    return rows


def anomaly_rows(windows):
    rows = []
    for window in windows:
        score = window.get('score')
        if not window.get('hard') and (score is None or score < .5):
            continue
        rows.append({
            'timestamp': window.get('timestamp'),
            'device': window.get('ip'),
            'layer': 'HARD_RULE' if window.get('hard') else 'IF',
            'score': score,
            'reason': window.get('reason') or '',
            'tier': window.get('desired_tier'),
            'ae_suppressed': bool(window.get('ae_suppressed')),
        })
    return rows


def tier_change_rows(events):
    rows = []
    for event in events:
        if event.get('action') != 'tier_changed':
            continue
        rows.append({
            'timestamp': event.get('timestamp'),
            'device': event.get('ip'),
            'old_tier': event.get('previous'),
            'new_tier': event.get('tier'),
            'trust': event.get('trust'),
        })
    return rows


def traffic_rows(windows):
    rows = []
    for window in windows:
        rows.append({
            'ts': window.get('timestamp'),
            'device': window.get('ip'),
            'packets': window.get('packets'),
            'bytes': window.get('bytes'),
            'proto': None,
            'tier': window.get('desired_tier'),
            'trust': window.get('trust'),
            'score': window.get('score'),
            'reason': window.get('reason'),
        })
    return rows


def topology(gateway, topology_cfg):
    devices = [device_view(d) for d in gateway.storage.devices().values() if not d.get('deleting')]
    lan = (topology_cfg or {}).get('lan', 'lan')
    wan = (topology_cfg or {}).get('wan', 'wan')
    return {
        'firewall': {'lan': lan, 'wan': wan},
        'devices': [{'ip': d['ip'], 'name': d['name'], 'tier': d['tier'], 'trust_score': d['trust_score']}
                    for d in devices],
        'links': [{'source': d['ip'], 'target': 'firewall', 'tier': d['tier']} for d in devices],
    }


def handle(server, method, path, query, body, authorized):
    """Dispatch one Phase 1-compatible request. Returns (code, payload_dict)."""
    g = server.gateway
    parts = [p for p in path.strip('/').split('/') if p]

    if method == 'POST' and parts == ['auth', 'login']:
        username = (body.get('username') or '').strip()
        password = body.get('password') or ''
        if not username or not password:
            return err('username and password are required', 400)
        if not hmac.compare_digest(password.encode(), server.token.encode()):
            return err('Invalid username or password', 401)
        return ok({'token': server.token, 'username': username, 'role': 'admin'},
                  msg='Login successful')

    # Public Phase 1 status (auth optional); still useful when logged out.
    if method == 'GET' and parts == ['status']:
        devices = [d for d in g.storage.devices().values() if not d.get('deleting')]
        return ok({
            'devices_total': len(devices),
            'devices_learning': sum(1 for d in devices if d.get('learning')),
            'devices_active': sum(1 for d in devices if not d.get('learning')),
            'devices_quarantine': sum(1 for d in devices if d.get('desired_tier') == 'QUARANTINE'),
            'auth_enabled': True,
            'cloud_api_ok': False,
            'cloud_api_url': None,
            'ready': g.status().get('ready'),
            'mode': server.mode,
        }, msg='TrustEdge API running')

    if not authorized:
        return err('authentication required', 401)

    try:
        if method == 'GET' and parts == ['device-types']:
            return ok([{'type': key, 'description': key, 'default_rate': 5}
                       for key in CONTAMINATION])

        if method == 'GET' and parts == ['attack-types']:
            return ok([
                {'type': 'port_scan', 'description': 'Hard-rule PORT_SCAN fixture window'},
                {'type': 'syn_flood', 'description': 'Mapped to hard-rule attack fixture'},
            ])

        if method == 'GET' and parts == ['devices']:
            return ok([device_view(d) for d in g.storage.devices().values() if not d.get('deleting')])

        if method == 'POST' and parts == ['devices']:
            ip = (body.get('ip') or '').strip()
            name = body.get('name') or f"device-{ip.split('.')[-1]}"
            device_type = body.get('type') or body.get('device_type') or 'custom'
            dst = body.get('dst') or '172.21.0.10'
            rate = body.get('rate', 5)
            if device_type not in CONTAMINATION:
                return err(f'Unknown device type {device_type!r}', 400)
            enrolled = g.register(ip, name, [dst], device_type, rate)
            return ok(device_view(g.storage.devices()[enrolled]),
                      msg=f'Device {enrolled} registered — entering LEARNING phase', code=201)

        if len(parts) >= 2 and parts[0] == 'devices':
            ip = parts[1]
            if method == 'GET' and len(parts) == 2:
                d = g._device(ip)
                return ok(device_view(d))
            if method == 'PATCH' and len(parts) == 2:
                d = g._device(ip)
                name = body.get('name', d['name'])
                destinations = d['destinations']
                if 'dst' in body and body['dst']:
                    destinations = [body['dst']] + [x for x in destinations if x != body['dst']]
                g.update(ip, name, destinations)
                return ok(device_view(g.storage.devices()[ip]), msg=f'Device {ip} updated')
            if method == 'DELETE' and len(parts) == 2:
                g.delete(ip)
                return ok(msg=f'Device {ip} removed')
            if method == 'GET' and len(parts) == 3 and parts[2] == 'history':
                g._device(ip)
                n = min(int((query.get('n') or ['100'])[0]), 1000)
                return ok(history_rows(g.storage.windows(ip, n)))
            if method == 'POST' and len(parts) == 3 and parts[2] == 'lift-quarantine':
                g.release(ip, 'Phase 1 dashboard lift-quarantine')
                return ok(device_view(g.storage.devices()[ip]), msg=f'{ip} released to CAUTIOUS')
            if method == 'POST' and len(parts) == 3 and parts[2] == 'rebaseline':
                g.rebaseline(ip)
                return ok(msg=f'{ip} rebaselined')
            if method == 'POST' and len(parts) == 3 and parts[2] == 'attack':
                if server.mode != 'simulation':
                    return err('attack simulation is only available in simulation mode', 400)
                g.window(ip, fixture(ip, True), 60)
                return ok(msg=f'Attack simulation window applied for {ip}')
            if method == 'DELETE' and len(parts) == 3 and parts[2] == 'attack':
                return ok(msg=f'Attack simulation cleared for {ip}')

        if method == 'POST' and parts == ['devices', 'lift-all-quarantine']:
            lifted = []
            for ip, d in list(g.storage.devices().items()):
                if d.get('desired_tier') == 'QUARANTINE' and not d.get('deleting'):
                    g.release(ip, 'Phase 1 dashboard lift-all-quarantine')
                    lifted.append(ip)
            return ok(lifted, msg=f'lifted {len(lifted)} devices')

        if method == 'GET' and parts == ['events', 'anomalies']:
            n = min(int((query.get('n') or ['200'])[0]), 1000)
            return ok(anomaly_rows(g.storage.windows(limit=n))[-n:])

        if method == 'GET' and parts == ['events', 'tier-changes']:
            return ok(tier_change_rows(g.storage.events()))

        if method == 'GET' and parts == ['traffic']:
            n = min(int((query.get('n') or ['500'])[0]), 2000)
            return ok(traffic_rows(g.storage.windows(limit=n))[-n:])

        if method == 'GET' and parts == ['topology']:
            return ok(topology(g, server.topology))

        if method == 'GET' and parts == ['audit-log']:
            n = min(int((query.get('n') or ['200'])[0]), 1000)
            rows = []
            for event in g.storage.events()[:n]:
                rows.append({
                    'ts': event.get('timestamp'),
                    'username': 'operator',
                    'role': 'admin',
                    'action': event.get('action'),
                    'target': event.get('ip', ''),
                    'detail': json.dumps({k: v for k, v in event.items()
                                          if k not in ('action', 'ip', 'timestamp')}),
                })
            return ok(rows)

        if method == 'GET' and parts[:1] == ['cloud']:
            return ok({} if parts[-1] != 'alerts' else [], msg='cloud telemetry omitted in Phase 2')

        if method == 'GET' and parts == ['users']:
            return ok([{'username': 'operator', 'role': 'admin'}])

        if parts[:1] == ['users']:
            return err('per-user RBAC is not enabled; use the gateway bearer token', 501)

        if parts == ['ws']:
            return err('websocket upgrades are not implemented on the compatibility API; polling continues to work', 501)

        return err('unknown Phase 1 compatibility endpoint', 404)
    except DetectionError as exc:
        return err(str(exc), 503)
    except PolicyError as exc:
        return err(str(exc), 503)
    except KeyError:
        return err('missing device or required field', 404)
    except (ValueError, TypeError) as exc:
        return err(str(exc), 400)
