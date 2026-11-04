"""Phase 1 dashboard API compatibility wrapper over the Phase 2 gateway.

Served under `/p1/*`. JWT + admin/operator/viewer roles are enforced via
phase1_auth. Cloud telemetry is omitted. Attack simulation maps to fixture
windows in simulation mode only. The Phase 2 console at `/` is unchanged.
"""
import json

from .detection import BASELINE_WINDOWS, CONTAMINATION, DetectionError
from .policy import PolicyError
from .simulation import fixture
from . import phase1_auth


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


def anomaly_rows(windows, names=None):
    names = names or {}
    rows = []
    for window in windows:
        score = window.get('score')
        if not window.get('hard') and (score is None or score < .5):
            continue
        layer = 'hard_rule' if window.get('hard') else (
            'autoencoder' if window.get('ae_suppressed') else 'isolation_forest')
        ts = window.get('timestamp')
        ip = window.get('ip')
        reason = window.get('reason') or ''
        rows.append({
            'ts': ts,
            'timestamp': ts,
            'device': ip,
            'name': names.get(ip, ip),
            'layer': layer,
            'score': score,
            'anomaly_score': score,
            'rule': reason,
            'reason': reason,
            'tier': window.get('desired_tier'),
            'ae_suppressed': bool(window.get('ae_suppressed')),
        })
    return rows


def tier_change_rows(events, names=None):
    names = names or {}
    rows = []
    for event in events:
        if event.get('action') != 'tier_changed':
            continue
        ts = event.get('timestamp')
        ip = event.get('ip')
        trust = event.get('trust')
        reason = event.get('reason') or event.get('detail') or ''
        rows.append({
            'ts': ts,
            'timestamp': ts,
            'device': ip,
            'name': names.get(ip, ip),
            'old_tier': event.get('previous'),
            'new_tier': event.get('tier'),
            'trust': trust,
            'trust_score': trust,
            'anomaly_score': event.get('score'),
            'reason': reason,
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
    """Shape matches Phase 1 `/topology`: `{nodes, edges}` for the original SVG map."""
    devices = [device_view(d) for d in gateway.storage.devices().values() if not d.get('deleting')]
    cfg = topology_cfg or {}
    gateway_ip = cfg.get('gateway') or '172.20.0.2'
    dns_ip = cfg.get('dns') or '172.21.0.12'
    nodes = [{
        'ip': d['ip'], 'name': d['name'], 'tier': d['tier'],
        'trust_score': d['trust_score'], 'learning': d['learning'], 'type': d['type'],
    } for d in devices]
    # Synthetic external sinks so the Phase 1 map has a WAN side without packet-graph state.
    externals = [
        {'ip': gateway_ip, 'name': 'gateway', 'tier': 'EXTERNAL', 'trust_score': None,
         'learning': False, 'type': 'external'},
        {'ip': dns_ip, 'name': 'dns', 'tier': 'EXTERNAL', 'trust_score': None,
         'learning': False, 'type': 'dns'},
    ]
    seen = {n['ip'] for n in nodes}
    for ext in externals:
        if ext['ip'] not in seen:
            nodes.append(ext)
            seen.add(ext['ip'])
    for d in devices:
        for dst in (gateway.storage.devices().get(d['ip'], {}) or {}).get('destinations') or []:
            if dst not in seen:
                nodes.append({'ip': dst, 'name': dst, 'tier': 'EXTERNAL', 'trust_score': None,
                              'learning': False, 'type': 'external'})
                seen.add(dst)
    edges = []
    for d in devices:
        dests = (gateway.storage.devices().get(d['ip'], {}) or {}).get('destinations') or []
        for dst in dests or [dns_ip]:
            edges.append({'source': d['ip'], 'target': dst, 'packets': 0, 'bytes': 0, 'last_seen': None})
    return {'nodes': nodes, 'edges': edges}


def device_snapshot(gateway):
    return [device_view(d) for d in gateway.storage.devices().values() if not d.get('deleting')]


def handle(server, method, path, query, body, bearer):
    """Dispatch one Phase 1-compatible request. Returns (code, payload_dict)."""
    g = server.gateway
    parts = [p for p in path.strip('/').split('/') if p]
    secret = phase1_auth.jwt_secret(server.token)
    phase1_auth.ensure_seed_users(g.storage)

    allowed, status, message, principal = phase1_auth.authorize(method, parts, bearer, secret)
    if not allowed:
        return err(message, status)

    if method == 'POST' and parts == ['auth', 'login']:
        username = (body.get('username') or '').strip()
        password = body.get('password') or ''
        if not username or not password:
            return err('username and password are required', 400)
        if g.storage.user_count() == 0:
            return err(
                'no Phase 1 users configured; set TRUSTEDGE_ADMIN_PASSWORD and restart',
                503)
        user = g.storage.get_user(username)
        if not user or not phase1_auth.verify_password_hash(password, user['password_hash']):
            return err('Invalid username or password', 401)
        token = phase1_auth.make_token(user['username'], user['role'], secret)
        return ok({'token': token, 'username': user['username'], 'role': user['role']},
                  msg='Login successful')

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
            'users_configured': g.storage.user_count() > 0,
        }, msg='TrustEdge API running')

    # Remaining routes require a principal (authorize already enforced JWT except public).
    if principal is None and not (method == 'GET' and parts == ['status']):
        # GET status is public; everything else past login must be authenticated.
        if not (method == 'POST' and parts == ['auth', 'login']):
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
            return ok(device_snapshot(g))

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
                return ok(device_view(g._device(ip)))
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
            names = {ip: d.get('name', ip) for ip, d in g.storage.devices().items()}
            return ok(anomaly_rows(g.storage.windows(limit=n), names)[-n:])

        if method == 'GET' and parts == ['events', 'tier-changes']:
            names = {ip: d.get('name', ip) for ip, d in g.storage.devices().items()}
            return ok(tier_change_rows(g.storage.events(), names))

        if method == 'GET' and parts == ['traffic']:
            n = min(int((query.get('n') or ['500'])[0]), 2000)
            return ok(traffic_rows(g.storage.windows(limit=n))[-n:])

        if method == 'GET' and parts == ['topology']:
            return ok(topology(g, server.topology))

        if method == 'GET' and parts == ['audit-log']:
            if principal and principal['role'] == 'viewer':
                return err('Forbidden — admin or operator role required', 403)
            n = min(int((query.get('n') or ['200'])[0]), 1000)
            rows = []
            for event in g.storage.events()[:n]:
                rows.append({
                    'ts': event.get('timestamp'),
                    'username': (principal or {}).get('username', ''),
                    'role': (principal or {}).get('role', ''),
                    'action': event.get('action'),
                    'target': event.get('ip', ''),
                    'detail': json.dumps({k: v for k, v in event.items()
                                          if k not in ('action', 'ip', 'timestamp')}),
                })
            return ok(rows)

        if method == 'GET' and parts[:1] == ['cloud']:
            return ok({} if parts[-1] != 'alerts' else [], msg='cloud telemetry omitted in Phase 2')

        if method == 'GET' and parts == ['users']:
            return ok(g.storage.list_users())

        if method == 'POST' and parts == ['users']:
            username = (body.get('username') or '').strip()
            password = body.get('password') or ''
            role = body.get('role', 'viewer')
            if not g.storage.create_user(username, phase1_auth.hash_password(password), role):
                return err(f"User '{username}' already exists", 409)
            return ok({'username': username, 'role': role}, msg='User created', code=201)

        if method == 'DELETE' and len(parts) == 2 and parts[0] == 'users':
            username = parts[1]
            if username == 'admin':
                return err('Cannot delete the default admin account', 403)
            if not g.storage.delete_user(username):
                return err(f"User '{username}' not found", 404)
            return ok(msg=f"User '{username}' deleted")

        if method == 'PATCH' and len(parts) == 2 and parts[0] == 'users':
            username = parts[1]
            role = body.get('role')
            if not role:
                return err('role is required', 400)
            if not g.storage.update_user_role(username, role):
                return err(f"User '{username}' not found", 404)
            return ok({'username': username, 'role': role}, msg=f"User '{username}' updated")

        return err('unknown Phase 1 compatibility endpoint', 404)
    except DetectionError as exc:
        return err(str(exc), 503)
    except PolicyError as exc:
        return err(str(exc), 503)
    except KeyError:
        return err('missing device or required field', 404)
    except (ValueError, TypeError) as exc:
        return err(str(exc), 400)
