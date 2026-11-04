"""Explicit offline fixtures; never used by the live collector."""
import itertools
from .features import Packet

_SEQ = itertools.count()


def fixture(ip, attack=False, vary=False):
    """Phase 1-shaped packet windows for simulation / unit tests.

    vary=False keeps a stable vector for reproducible Isolation Forest scoring tests.
    vary=True adds mild per-call diversity so a 50-window baseline can actually train
    (identical windows collapse sklearn IsolationForest calibration).
    """
    if attack:
        return [Packet(ip, '192.0.2.10', 60, 'tcp', p, True, timestamp=p * .01, sport=12345, tcp_flags='S')
                for p in range(1, 101)]
    if not vary:
        return [Packet(ip, '192.0.2.10', 500, 'tcp', 443, timestamp=i * 3., sport=12345, tcp_flags='PA')
                for i in range(20)]
    n = next(_SEQ)
    count = 18 + (n % 5)
    return [Packet(ip, '192.0.2.10', 420 + ((n + i) % 90), 'tcp', 443, False,
                   timestamp=i * 2.8 + (n % 11) * 0.05, sport=12340 + (n % 7), tcp_flags='PA')
            for i in range(count)]
