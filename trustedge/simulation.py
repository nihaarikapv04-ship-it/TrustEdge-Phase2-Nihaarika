"""Explicit offline fixtures; never used by the live collector."""
from .features import Packet

def fixture(ip, attack=False):
    if attack:
        return [Packet(ip, '192.0.2.10', 60, 'tcp', p, True, timestamp=p * .01, sport=12345, tcp_flags='S') for p in range(1, 101)]
    return [Packet(ip, '192.0.2.10', 500, 'tcp', 443, timestamp=i * 3., sport=12345, tcp_flags='PA') for i in range(20)]
