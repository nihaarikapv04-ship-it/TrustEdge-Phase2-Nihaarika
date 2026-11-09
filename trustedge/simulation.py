"""Explicit offline fixtures; never used by the live collector."""
import itertools
from .features import Packet

_SEQ = itertools.count()

# Dashboard attack types → bounded in-memory packet windows (no external flooding).
ATTACK_TYPES = (
    'syn_flood', 'port_scan', 'data_exfil', 'icmp_flood', 'lateral',
)


def fixture(ip, attack=False, vary=False):
    """Phase 1-shaped packet windows for simulation / unit tests.

    vary=False keeps a stable vector for reproducible Isolation Forest scoring tests.
    vary=True adds mild per-call diversity so a 50-window baseline can actually train
    (identical windows collapse sklearn IsolationForest calibration).
    """
    if attack:
        # Original Phase 1 attack fixture: 100 distinct dports with SYN → PORT_SCAN
        # (syn_count == 100 is not >100, so SYN_FLOOD does not fire). Dashboard
        # attack types use attack_fixture() instead.
        return [Packet(ip, '192.0.2.10', 60, 'tcp', p, True, timestamp=p * .01,
                       sport=12345, tcp_flags='S') for p in range(1, 101)]
    if not vary:
        # Mid-hull of the vary=True distribution (size≈460, IAT=2.8). The older
        # 500-byte / 3.0s IAT stable window sat outside the sklearn 1.6.1 IF hull
        # after a vary=True baseline and false-quarantined Pi-compatible parity.
        return [Packet(ip, '192.0.2.10', 460, 'tcp', 443, False,
                       timestamp=i * 2.8, sport=12343, tcp_flags='PA')
                for i in range(20)]
    n = next(_SEQ)
    count = 18 + (n % 5)
    return [Packet(ip, '192.0.2.10', 420 + ((n + i) % 90), 'tcp', 443, False,
                   timestamp=i * 2.8 + (n % 11) * 0.05, sport=12340 + (n % 7), tcp_flags='PA')
            for i in range(count)]


def attack_fixture(ip, attack_type='syn_flood'):
    """Bounded lab-only attack windows that exercise Phase 1 hard rules / ML path.

    Packets are synthetic and processed through Gateway.window (same pipeline as
    Scapy capture). They are never sent on a physical NIC or the home WAN.
    """
    kind = (attack_type or 'syn_flood').strip().lower()
    if kind not in ATTACK_TYPES:
        raise ValueError(f'unsupported attack type {attack_type!r}; choose one of {ATTACK_TYPES}')
    # SYN flood: syn_count > 100 and almost no non-SYN TCP → HARD_RULE SYN_FLOOD
    if kind in ('syn_flood',):
        return [Packet(ip, '192.0.2.10', 60, 'tcp', 80, True, timestamp=p * .01,
                       sport=12345, tcp_flags='S') for p in range(1, 110)]
    # Port scan / lateral: high destination-port entropy → PORT_SCAN.
    # Use non-SYN flags so the SYN_FLOOD hard rule (syn>100) does not fire first.
    if kind in ('port_scan', 'lateral'):
        dests = [f'192.0.2.{(i % 200) + 1}' for i in range(120)]
        return [Packet(ip, dests[i], 60, 'tcp', 1024 + i, False, timestamp=i * .02,
                       sport=40000 + (i % 50), tcp_flags='PA') for i in range(120)]
    # Data exfil / ICMP flood: packet count > 5000 → VOLUME_ANOMALY (in-memory only)
    if kind in ('data_exfil', 'icmp_flood'):
        proto = 'icmp' if kind == 'icmp_flood' else 'tcp'
        port = 0 if proto == 'icmp' else 443
        return [Packet(ip, '192.0.2.10', 64, proto, port, False, timestamp=i * .001,
                       sport=0 if proto == 'icmp' else 50000, tcp_flags='' if proto == 'icmp' else 'PA')
                for i in range(5001)]
    raise ValueError(f'unsupported attack type {attack_type!r}')


def traffic_summary(packets):
    """Compact inspector fields derived from a processed window's packets."""
    if not packets:
        return {'proto': None, 'src': None, 'dst': None, 'sport': None, 'dport': None,
                'size': 0, 'flags': None, 'direction': 'outbound'}
    from collections import Counter
    proto_counts = Counter((p.protocol or '').lower() for p in packets)
    proto = proto_counts.most_common(1)[0][0] or None
    dst_counts = Counter(p.dst for p in packets)
    dst = dst_counts.most_common(1)[0][0]
    src = packets[0].src
    # Dominant transport ports; ICMP keeps ports null (not fake zeros for display).
    if proto == 'icmp':
        sport = dport = None
        flags = None
    else:
        sport = packets[0].sport or None
        dport_counts = Counter(p.port for p in packets if p.port)
        dport = dport_counts.most_common(1)[0][0] if dport_counts else (packets[0].port or None)
        flag_counts = Counter(p.tcp_flags for p in packets if p.tcp_flags)
        flags = flag_counts.most_common(1)[0][0] if flag_counts else None
    return {
        'proto': proto,
        'src': src,
        'dst': dst,
        'sport': sport,
        'dport': dport,
        'size': sum(p.size for p in packets),
        'flags': flags,
        'direction': 'outbound',
    }