"""Phase 1 dashboard API compatibility wrapper over the Phase 2 gateway.

Served under `/p1/*`. JWT + admin/operator/viewer roles are enforced via
phase1_auth. Cloud telemetry is omitted. Attack simulation injects bounded
fixture windows through Gateway.window (same path as Scapy capture) — never
a second detection engine and never external flooding.
"""
import json
import threading
import time

from datetime import datetime, timezone

from .detection import BASELINE_WINDOWS, CONTAMINATION, DetectionError
from .policy import PolicyError
from .simulation import ATTACK_TYPES, attack_fixture
from . import phase1_auth

# Bounded lab attack runner: inject through Gateway.window only (no NIC flood).
_ATTACK_MAX_INJECTIONS = 4
_ATTACK_INTERVAL_SEC = 12.0
_AUDIT_SKIP = frozenset({'window', 'policy_applied'})

# Five-device lab topology used for the Mac/Pi demonstration checklist.
LAB_DEMO_IPS = (
    '172.20.0.10', '172.20.0.11', '172.20.0.12', '172.20.0.13', '172.20.0.14',
)


def ok(data=None, msg='ok', code=200):
    body = {'status': 'ok', 'message': msg}
    if data is not None:
        body['data'] = data
    return code, body


def err(msg, code=400):
    return code, {'status': 'error', 'message': msg}


def _attack_state(server):
    state = getattr(server, 'attack_simulations', None)
    if state is None:
        server.attack_simulations = {}
        state = server.attack_simulations
    return state


def _latest_window(gateway, ip):
    rows = gateway.storage.windows(ip, 1)
    return rows[0] if rows else None


def _stop_attack_runner(server, ip):
    """Signal stop and join the runner thread. Returns prior entry or None."""
    state = _attack_state(server)
    entry = state.pop(ip, None)
    if entry is None:
        return None
    stop = entry.get('stop')
    if stop is not None:
        stop.set()
    thread = entry.get('thread')
    if thread is not None and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=8)
    return entry


def _start_attack_runner(server, ip, attack_type, actor=None, role=None):
    """Inject the first window synchronously, then continue on a bounded daemon."""
    state = _attack_state(server)
    if ip in state:
        raise RuntimeError(f'attack simulation already running for {ip}; stop it first')
    gateway = server.gateway
    packets = attack_fixture(ip, attack_type)
    gateway.window(ip, packets, 60)
    stop = threading.Event()

    def _run():
        injections = 1
        try:
            while injections < _ATTACK_MAX_INJECTIONS:
                if stop.wait(_ATTACK_INTERVAL_SEC):
                    break
                try:
                    gateway.window(ip, attack_fixture(ip, attack_type), 60)
                    injections += 1
                except Exception as exc:
                    with gateway.lock:
                        with gateway.storage.transaction():
                            gateway.storage.event(
                                action='attack_simulation_error', ip=ip,
                                attack_type=attack_type, error=str(exc),
                                actor=actor, role=role)
                    break
        finally:
            cur = _attack_state(server).get(ip)
            if cur is not None and cur.get('stop') is stop:
                _attack_state(server).pop(ip, None)
                with gateway.lock:
                    with gateway.storage.transaction():
                        gateway.storage.event(
                            action='attack_simulation_stopped', ip=ip,
                            attack_type=attack_type, reason='runner_finished',
                            injections=injections, actor=actor, role=role)

    thread = threading.Thread(target=_run, name=f'trustedge-attack-{ip}', daemon=True)
    state[ip] = {
        'type': attack_type,
        'started_at': time.time(),
        'stop': stop,
        'thread': thread,
        'actor': actor,
        'role': role,
    }
    thread.start()
    return state[ip]


def _device_is_stale(device, last_seen, window_seconds=None):
    """True when a non-learning device has not reported within ~3 capture windows."""
    if device.get('learning'):
        return False
    ts = _parse_ts(last_seen)
    if ts is None:
        return True
    try:
        cadence = float(window_seconds) if window_seconds not in (None, '') else 60.0
    except (TypeError, ValueError):
        cadence = 60.0
    cadence = max(5.0, min(cadence, 600.0))
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    return age > (cadence * 3.0)


def device_view(device, server=None):
    signatures = device.get('signature_state') or {}
    destinations = device.get('destinations') or []
    attacking = False
    window_seconds = None
    if server is not None:
        attacking = device['ip'] in _attack_state(server)
        window_seconds = getattr(server, 'window_seconds', None)
    current_packets = 0
    last_seen = None
    if server is not None:
        latest = _latest_window(server.gateway, device['ip'])
        if latest:
            current_packets = int(latest.get('packets') or 0)
            last_seen = latest.get('timestamp')
    seen = last_seen or device.get('last_seen_at')
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
        'is_attacking': attacking,
        'baseline_windows': len(device.get('baseline') or []),
        'baseline_required': BASELINE_WINDOWS,
        'baseline_remaining': max(0, BASELINE_WINDOWS - len(device.get('baseline') or [])),
        'learning_started_at': device.get('learning_started_at'),
        'learning_completed_at': device.get('learning_completed_at'),
        'baseline_complete': (not bool(device.get('learning'))) and (
            len(device.get('baseline') or []) >= BASELINE_WINDOWS
            or bool((device.get('model_info') or {}))),
        'current_packets': current_packets,
        'anomaly_streak': device.get('anomaly_streak', 0),
        'normal_streak': device.get('normal_streak', 0),
        'signatures': signatures.get('count', 0),
        'threshold': signatures.get('threshold', .7),
        'sig_complete': signatures.get('complete', False),
        'last_seen': seen,
        'first_seen': device.get('first_seen_at'),
        'mac': device.get('mac'),
        'enrollment_status': device.get('enrollment_status', 'enrolled'),
        'stale': _device_is_stale(device, seen, window_seconds),
        'desired_tier': device.get('desired_tier'),
        'applied_tier': device.get('applied_tier'),
        'enforcement_pending': (
            (device.get('applied_tier') or device.get('desired_tier')) != device.get('desired_tier')
        ),
        'previous_tier': device.get('previous_tier'),
        'tier_changed_at': device.get('tier_changed_at'),
        'model_ready': bool((device.get('model_info') or {})),
        'feature_schema': device.get('feature_schema'),
    }


def _parse_ts(value):
    if not value:
        return None
    text = str(value).replace('T', ' ').replace('Z', '')
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f'):
        try:
            return datetime.strptime(text[:26], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def learning_status(gateway, server=None):
    """Aggregate baseline-learning progress from persisted device + metadata state."""
    devices = [d for d in gateway.storage.devices().values() if not d.get('deleting')]
    views = [device_view(d, server) for d in devices]
    required = BASELINE_WINDOWS
    per_device = []
    for view in views:
        collected = min(int(view.get('baseline_windows') or 0), required)
        complete = bool(view.get('baseline_complete'))
        if complete:
            collected = required
        per_device.append({
            'ip': view['ip'],
            'name': view['name'],
            'type': view['type'],
            'learning': view['learning'],
            'baseline_windows': collected,
            'baseline_required': required,
            'baseline_remaining': 0 if complete else max(0, required - collected),
            'complete': complete,
            'learning_started_at': view.get('learning_started_at'),
            'learning_completed_at': view.get('learning_completed_at'),
        })
    completed = sum(1 for row in per_device if row['complete'])
    total = len(per_device)
    lab_present = {row['ip'] for row in per_device}
    lab_enrolled = all(ip in lab_present for ip in LAB_DEMO_IPS)
    lab_complete = lab_enrolled and all(
        next((r for r in per_device if r['ip'] == ip), {}).get('complete') for ip in LAB_DEMO_IPS)
    all_enrolled_ready = (
        total > 0
        and all(not d.get('learning') for d in devices)
        and all(gateway.storage.has_model(d['ip']) for d in devices)
    )
    # Lab demo (any of the five lab IPs enrolled): require all five present + complete.
    # Unit/simulation fixtures that use other IPs only require enrolled devices ready.
    using_lab_topology = any(ip in lab_present for ip in LAB_DEMO_IPS)
    attacks_ready = all_enrolled_ready and (lab_complete if using_lab_topology else True)
    started_at = gateway.storage.get_meta('learning_session_started_at')
    if not started_at:
        starts = [r['learning_started_at'] for r in per_device if r.get('learning_started_at')]
        started_at = min(starts) if starts else None
    completed_at = gateway.storage.get_meta('baseline_complete_at')
    if attacks_ready and not completed_at:
        # Backfill durable completion for labs that finished before this metadata existed.
        completed_at = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        with gateway.lock:
            with gateway.storage.transaction():
                gateway.storage.set_meta('baseline_complete_at', completed_at)
    elapsed_seconds = None
    start_dt = _parse_ts(started_at)
    end_dt = _parse_ts(completed_at) or datetime.now(timezone.utc)
    if start_dt:
        elapsed_seconds = max(0, int((end_dt - start_dt).total_seconds()))
    status = 'COMPLETE' if attacks_ready else (
        'IN_PROGRESS' if any(r['baseline_windows'] > 0 or r['learning'] for r in per_device) else 'PENDING')
    return {
        'status': status,
        'baseline_required': required,
        'devices_total': total,
        'devices_complete': completed,
        'devices_learning': sum(1 for r in per_device if r['learning']),
        'lab_devices_expected': len(LAB_DEMO_IPS),
        'lab_devices_enrolled': sum(1 for ip in LAB_DEMO_IPS if ip in lab_present),
        'lab_devices_complete': sum(
            1 for ip in LAB_DEMO_IPS
            if next((r for r in per_device if r['ip'] == ip), {}).get('complete')),
        'attacks_ready': attacks_ready,
        'learning_started_at': started_at,
        'baseline_complete_at': completed_at,
        'elapsed_seconds': elapsed_seconds,
        'message': (
            'Baseline learning COMPLETE — system ready for attack testing.'
            if attacks_ready else
            'Collecting 50 valid baseline windows per device. Attack simulation is blocked until all five lab devices finish.'
            if status == 'IN_PROGRESS' else
            'Waiting for enrolled devices and valid traffic through the firewall.'
        ),
        'devices': per_device,
    }


def attacks_allowed(gateway):
    return bool(learning_status(gateway).get('attacks_ready'))


def history_rows(windows):
    rows = []
    for window in reversed(windows):
        ts = window.get('timestamp')
        trust = window.get('trust')
        rows.append({
            'ts': ts,
            'timestamp': ts,
            'trust': trust,
            'trust_score': trust,
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
        action = event.get('action')
        ts = event.get('timestamp')
        ip = event.get('ip')
        trust = event.get('trust')
        if action == 'tier_changed':
            previous = event.get('previous')
            tier = event.get('tier')
            reason = event.get('reason') or event.get('detail') or ''
            # Q→C never happens via windows (operator release only). The paired
            # quarantine_release_requested row is the canonical Manual entry —
            # skip the reconcile twin so the log does not double-count lifts.
            if previous == 'QUARANTINE' and tier == 'CAUTIOUS' and not reason:
                continue
            rows.append({
                'ts': ts,
                'timestamp': ts,
                'device': ip,
                'name': names.get(ip, ip),
                'old_tier': previous,
                'new_tier': tier,
                'trust': trust,
                'trust_score': trust,
                'anomaly_score': event.get('score'),
                'reason': reason,
            })
        elif action == 'quarantine_release_requested':
            rows.append({
                'ts': ts,
                'timestamp': ts,
                'device': ip,
                'name': names.get(ip, ip),
                'old_tier': 'QUARANTINE',
                'new_tier': 'CAUTIOUS',
                'trust': 0.55 if trust is None else trust,
                'trust_score': 0.55 if trust is None else trust,
                'anomaly_score': None,
                'reason': 'manual lift',
            })
    return rows


def _proto_label(value):
    if value is None or value == '':
        return None
    if isinstance(value, int):
        return {6: 'tcp', 17: 'udp', 1: 'icmp'}.get(value, str(value))
    text = str(value).lower()
    if text in ('6', 'tcp'):
        return 'tcp'
    if text in ('17', 'udp'):
        return 'udp'
    if text in ('1', 'icmp'):
        return 'icmp'
    return text


def traffic_rows(windows, proto_filter=None):
    want = _proto_label(proto_filter) if proto_filter not in (None, '', []) else None
    if isinstance(proto_filter, list):
        want = _proto_label(proto_filter[0]) if proto_filter else None
    rows = []
    for window in windows:
        proto = _proto_label(window.get('proto'))
        if want and proto != want:
            continue
        size = window.get('size')
        if size is None:
            size = window.get('bytes')
        sport = window.get('sport')
        dport = window.get('dport')
        # ICMP must not show fabricated ports.
        if proto == 'icmp':
            sport = dport = None
        rows.append({
            'ts': window.get('timestamp'),
            'timestamp': window.get('timestamp'),
            'device': window.get('ip'),
            'packets': window.get('packets'),
            'bytes': window.get('bytes'),
            'size': size,
            'proto': proto,
            'src': window.get('src') or window.get('ip'),
            'dst': window.get('dst'),
            'sport': sport,
            'dport': dport,
            'flags': window.get('flags'),
            'direction': window.get('direction') or 'outbound',
            'tier': window.get('desired_tier'),
            'trust': window.get('trust'),
            'score': window.get('score'),
            'reason': window.get('reason'),
            'verdict': window.get('reason') if window.get('hard') else (
                'anomaly' if (window.get('score') or 0) >= .5 else 'allow'),
        })
    return rows


def topology(gateway, topology_cfg, server=None):
    """Shape matches Phase 1 `/topology`: `{nodes, edges}` for the original SVG map."""
    devices = [device_view(d, server) for d in gateway.storage.devices().values() if not d.get('deleting')]
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


def device_snapshot(gateway, server=None):
    return [device_view(d, server) for d in gateway.storage.devices().values() if not d.get('deleting')]


def _audit_action_label(action):
    return {
        'registered': 'REGISTER_DEVICE',
        'device_updated': 'UPDATE_DEVICE',
        'deleted': 'REMOVE_DEVICE',
        'rebaseline': 'REBASELINE_DEVICE',
        'quarantine_release_requested': 'LIFT_QUARANTINE',
        'tier_changed': 'TIER_CHANGED',
        'attack_simulation_started': 'START_ATTACK',
        'attack_simulation_stopped': 'STOP_ATTACK',
        'attack_simulation_error': 'ATTACK_ERROR',
        'baseline_learning_complete': 'BASELINE_COMPLETE',
        'policy_applied': 'POLICY_APPLIED',
        'enforcement_failed': 'ENFORCEMENT_FAILED',
        'detection_failed': 'DETECTION_FAILED',
        'window': 'WINDOW',
    }.get(action or '', (action or 'EVENT').upper())


def network_load(gateway, limit=120):
    """Lab traffic rates derived from persisted detection windows (not host NIC)."""
    windows = list(reversed(gateway.storage.windows(limit=min(limit, 500))))
    series = []
    for window in windows:
        seconds = float(window.get('seconds') or 60) or 60.0
        packets = int(window.get('packets') or 0)
        nbytes = int(window.get('bytes') or window.get('size') or 0)
        series.append({
            'ts': window.get('timestamp'),
            'timestamp': window.get('timestamp'),
            'device': window.get('ip'),
            'packets': packets,
            'bytes': nbytes,
            'pps': round(packets / seconds, 3),
            'bps': round((nbytes * 8) / seconds, 3),
            'scope': 'docker_lab',
        })
    total_packets = sum(row['packets'] for row in series)
    total_bytes = sum(row['bytes'] for row in series)
    by_device = {}
    for row in series:
        ip = row['device'] or 'unknown'
        bucket = by_device.setdefault(ip, {'device': ip, 'packets': 0, 'bytes': 0})
        bucket['packets'] += row['packets']
        bucket['bytes'] += row['bytes']
    return {
        'scope': 'docker_lab',
        'host_nic': 'unavailable',
        'note': 'Rates are from firewall detection windows on lab traffic, not host eth0/eth1 counters.',
        'total_packets': total_packets,
        'total_bytes': total_bytes,
        'devices': sorted(by_device.values(), key=lambda r: r['packets'], reverse=True),
        'series': series,
    }


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

    if method == 'POST' and parts == ['auth', 'refresh']:
        # Principal already validated by authorize(); mint a fresh expiry so the
        # dashboard can stay connected without forcing a full page reload.
        if principal is None:
            return err('authentication required', 401)
        token = phase1_auth.make_token(principal['username'], principal['role'], secret)
        return ok({'token': token, 'username': principal['username'], 'role': principal['role']},
                  msg='Token refreshed')

    if method == 'GET' and parts == ['auth', 'session']:
        # Authenticated liveness probe for the dashboard heartbeat. Unlike GET /status
        # (public), this fails closed on missing/expired/invalid JWTs.
        if principal is None:
            return err('authentication required', 401)
        return ok({
            'username': principal['username'],
            'role': principal['role'],
            'authenticated': True,
        }, msg='Session valid')

    if method == 'GET' and parts == ['status']:
        from .dashboard import host_health
        devices = [d for d in g.storage.devices().values() if not d.get('deleting')]
        load = network_load(g, limit=40)
        learn = learning_status(g, server)
        capture = getattr(server, 'collector', None)
        capture_health = None
        if capture is not None:
            capture_health = dict(
                running=bool(getattr(capture, 'running', False)),
                error=getattr(capture, 'error', None),
                dropped=getattr(capture, 'dropped', 0))
        db_counts = g.storage.counts()
        return ok({
            'devices_total': len(devices),
            'devices_learning': sum(1 for d in devices if d.get('learning')),
            'devices_active': sum(1 for d in devices if not d.get('learning')),
            'devices_quarantine': sum(1 for d in devices if d.get('desired_tier') == 'QUARANTINE'),
            'auth_enabled': True,
            'cloud_api_ok': False,
            'cloud_api_url': None,
            'cloud_telemetry': 'disabled',
            'ready': g.status().get('ready'),
            'mode': server.mode,
            'users_configured': g.storage.user_count() > 0,
            'attacks_running': list(_attack_state(server).keys()),
            'attacks_ready': learn['attacks_ready'],
            'learning': learn,
            'network_load': {
                'scope': load['scope'],
                'total_packets': load['total_packets'],
                'total_bytes': load['total_bytes'],
                'host_nic': load['host_nic'],
            },
            'health': host_health(g.storage.path),
            'capture': capture_health,
            'database': {
                'path': g.storage.path,
                'schema_version': g.storage.get_meta('schema_version'),
                'integrity': g.storage.integrity_check(),
                'counts': db_counts,
            },
            'firewall': {
                'ready': bool(g.status().get('ready')),
                'error': g.status().get('error'),
                'enforcement_pending': sum(
                    1 for d in devices
                    if (d.get('applied_tier') or d.get('desired_tier')) != d.get('desired_tier')),
            },
        }, msg='TrustEdge API running (local-only; cloud telemetry disabled)')

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
                {'type': 'syn_flood', 'description': 'Bounded SYN flood fixture → HARD_RULE SYN_FLOOD'},
                {'type': 'port_scan', 'description': 'High dest-port entropy fixture → HARD_RULE PORT_SCAN'},
                {'type': 'data_exfil', 'description': 'High packet-count fixture → HARD_RULE VOLUME_ANOMALY'},
                {'type': 'icmp_flood', 'description': 'Bounded ICMP volume fixture → HARD_RULE VOLUME_ANOMALY'},
                {'type': 'lateral', 'description': 'Multi-destination port sweep → HARD_RULE PORT_SCAN'},
            ])

        if method == 'GET' and parts == ['learning-status']:
            return ok(learning_status(g, server))

        if method == 'GET' and parts == ['devices']:
            return ok(device_snapshot(g, server))

        if method == 'POST' and parts == ['devices']:
            ip = (body.get('ip') or '').strip()
            name = body.get('name') or f"device-{ip.split('.')[-1]}"
            device_type = body.get('type') or body.get('device_type') or 'custom'
            dst = body.get('dst') or '172.21.0.10'
            rate = body.get('rate', 5)
            if device_type not in CONTAMINATION:
                return err(f'Unknown device type {device_type!r}', 400)
            enrolled = g.register(ip, name, [dst], device_type, rate)
            return ok(device_view(g.storage.devices()[enrolled], server),
                      msg=f'Device {enrolled} registered — entering LEARNING phase', code=201)

        if len(parts) >= 2 and parts[0] == 'devices':
            ip = parts[1]
            if method == 'GET' and len(parts) == 2:
                return ok(device_view(g._device(ip), server))
            if method == 'PATCH' and len(parts) == 2:
                d = g._device(ip)
                name = body.get('name', d['name'])
                destinations = d['destinations']
                if 'dst' in body and body['dst']:
                    destinations = [body['dst']] + [x for x in destinations if x != body['dst']]
                g.update(ip, name, destinations)
                return ok(device_view(g.storage.devices()[ip], server), msg=f'Device {ip} updated')
            if method == 'DELETE' and len(parts) == 2:
                g.delete(ip)
                _attack_state(server).pop(ip, None)
                return ok(msg=f'Device {ip} removed')
            if method == 'GET' and len(parts) == 3 and parts[2] == 'history':
                g._device(ip)
                n = min(int((query.get('n') or ['100'])[0]), 1000)
                return ok(history_rows(g.storage.windows(ip, n)))
            if method == 'POST' and len(parts) == 3 and parts[2] == 'lift-quarantine':
                g.release(
                    ip,
                    'Phase 1 dashboard lift-quarantine',
                    actor=(principal or {}).get('username'),
                    role=(principal or {}).get('role'),
                )
                return ok(device_view(g.storage.devices()[ip], server), msg=f'{ip} released to CAUTIOUS')
            if method == 'POST' and len(parts) == 3 and parts[2] == 'rebaseline':
                g.rebaseline(ip)
                return ok(msg=f'{ip} rebaselined')
            if method == 'POST' and len(parts) == 3 and parts[2] == 'attack':
                # Bounded fixture windows through Gateway.window (same path as capture).
                # Allowed in simulation and live lab; never emits packets on physical WAN.
                attack_type = (body.get('type') or 'syn_flood').strip().lower()
                if attack_type not in ATTACK_TYPES:
                    return err(f'unsupported attack type {attack_type!r}', 400)
                learn = learning_status(g, server)
                if not learn.get('attacks_ready'):
                    return err(
                        'attack simulation blocked until baseline learning is COMPLETE '
                        f'({learn.get("lab_devices_complete", 0)}/{learn.get("lab_devices_expected", 5)} '
                        'lab devices finished 50 valid windows)',
                        403)
                g._device(ip)
                if ip in _attack_state(server):
                    return err(f'attack simulation already running for {ip}; stop it first', 409)
                actor = (principal or {}).get('username')
                role = (principal or {}).get('role')
                try:
                    _start_attack_runner(server, ip, attack_type, actor=actor, role=role)
                except RuntimeError as exc:
                    return err(str(exc), 409)
                except ValueError as exc:
                    return err(str(exc), 400)
                with g.lock:
                    with g.storage.transaction():
                        g.storage.event(action='attack_simulation_started', ip=ip, attack_type=attack_type,
                                        actor=actor, role=role, mode=server.mode)
                return ok(device_view(g.storage.devices()[ip], server),
                          msg=f'Attack simulation started for {ip} ({attack_type})')
            if method == 'DELETE' and len(parts) == 3 and parts[2] == 'attack':
                g._device(ip)
                prior = _stop_attack_runner(server, ip)
                if prior is None:
                    return err(f'no attack simulation running for {ip}', 404)
                with g.lock:
                    with g.storage.transaction():
                        g.storage.event(action='attack_simulation_stopped', ip=ip,
                                        attack_type=prior.get('type'),
                                        actor=(principal or {}).get('username'),
                                        role=(principal or {}).get('role'),
                                        mode=server.mode, reason='operator_stop')
                return ok(device_view(g.storage.devices()[ip], server),
                          msg=f'Attack simulation stopped for {ip}')
        if method == 'POST' and parts == ['devices', 'lift-all-quarantine']:
            lifted = []
            actor = (principal or {}).get('username')
            role = (principal or {}).get('role')
            for ip, d in list(g.storage.devices().items()):
                if d.get('deleting'):
                    continue
                if d.get('desired_tier') == 'QUARANTINE' or d.get('applied_tier') == 'QUARANTINE':
                    g.release(ip, 'Phase 1 dashboard lift-all-quarantine', actor=actor, role=role)
                    lifted.append(ip)
            return ok(lifted, msg=f'lifted {len(lifted)} devices')

        if method == 'GET' and parts == ['events', 'anomalies']:
            n = min(int((query.get('n') or ['200'])[0]), 1000)
            names = {ip: d.get('name', ip) for ip, d in g.storage.devices().items()}
            return ok(anomaly_rows(g.storage.windows(limit=n), names)[-n:])

        if method == 'GET' and parts == ['events', 'tier-changes']:
            names = {ip: d.get('name', ip) for ip, d in g.storage.devices().items()}
            # Filter at storage — unfiltered events() is flooded by window/policy_applied.
            return ok(tier_change_rows(
                g.storage.events(
                    actions=('tier_changed', 'quarantine_release_requested'),
                    limit=500,
                ),
                names,
            ))

        if method == 'GET' and parts == ['traffic']:
            n = min(int((query.get('n') or ['500'])[0]), 2000)
            proto = (query.get('proto') or [None])[0]
            return ok(traffic_rows(g.storage.windows(limit=n), proto_filter=proto)[-n:])

        if method == 'GET' and parts == ['network-load']:
            n = min(int((query.get('n') or ['120'])[0]), 500)
            return ok(network_load(g, limit=n))

        if method == 'GET' and parts == ['topology']:
            return ok(topology(g, server.topology, server))

        if method == 'GET' and parts == ['audit-log']:
            if principal and principal['role'] == 'viewer':
                return err('Forbidden — admin or operator role required', 403)
            n = min(int((query.get('n') or ['200'])[0]), 1000)
            # Pull a filtered set so window/policy_applied noise cannot crowd out
            # tier/enforcement/operator actions (json_extract path in storage.events).
            wanted = (
                'tier_changed', 'enforcement_failed', 'quarantine_release_requested',
                'registered', 'deleted', 'device_updated', 'rebaseline',
                'detection_failed', 'baseline_learning_complete',
                'attack_simulation_started', 'attack_simulation_stopped',
                'policy_applied',
            )
            rows = []
            for event in g.storage.events(actions=wanted, limit=max(n * 2, 200)):
                action = event.get('action')
                if action in _AUDIT_SKIP:
                    continue
                detail = {k: v for k, v in event.items()
                          if k not in ('action', 'ip', 'timestamp', 'id', 'actor', 'role')}
                rows.append({
                    'ts': event.get('timestamp'),
                    'timestamp': event.get('timestamp'),
                    'username': event.get('actor') or event.get('username') or 'system',
                    'role': event.get('role') or 'system',
                    'action': _audit_action_label(action),
                    'raw_action': action,
                    'target': event.get('ip', ''),
                    'detail': json.dumps(detail, default=str),
                    'ip_addr': event.get('ip', ''),
                    'previous': event.get('previous'),
                    'new_state': event.get('tier'),
                    'reason': event.get('reason') or event.get('error'),
                    'result': 'error' if action and ('fail' in action or 'error' in action) else 'ok',
                })
                if len(rows) >= n:
                    break
            return ok(rows)

        if method == 'GET' and parts == ['enforcement']:
            n = min(int((query.get('n') or ['100'])[0]), 500)
            ip = (query.get('ip') or [None])[0]
            return ok(g.storage.enforcement(ip=ip, limit=n))

        if method == 'GET' and parts[:1] == ['cloud']:
            return ok(
                [] if parts[-1] == 'alerts' else {
                    'enabled': False,
                    'uploads': 0,
                    'message': (
                        'Cloud telemetry is disabled. TrustEdge Phase A is local-only; '
                        'detection, trust, database and firewall enforcement do not phone home.'
                    ),
                },
                msg='cloud telemetry disabled (local-only Phase A)')

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
