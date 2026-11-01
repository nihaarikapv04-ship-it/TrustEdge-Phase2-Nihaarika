"""Phase 1's ordered 14-feature contract, from packet metadata only."""
from collections import Counter
from dataclasses import dataclass
import math
import numpy as np

FEATURE_SCHEMA = 'phase1-14-v1'
FEATURE_NAMES = ('total_packets', 'total_bytes', 'duration', 'mean_iat',
                 'unique_dports', 'unique_destinations', 'syn_count', 'mean_size',
                 'std_size', 'tcp_fraction', 'udp_fraction', 'icmp_fraction',
                 'std_iat', 'destination_port_entropy')

@dataclass(frozen=True)
class Packet:
    src: str
    dst: str
    size: int
    protocol: str
    port: int = 0
    syn: bool = False
    timestamp: float | None = None
    sport: int = 0
    tcp_flags: str = ''

def extract(packets, seconds):
    if seconds <= 0:
        raise ValueError('window must be positive')
    if not packets:
        return None
    if any(p.timestamp is None or not math.isfinite(p.timestamp) or p.size < 0 for p in packets):
        raise ValueError('Phase 1 requires finite capture timestamps and complete packet lengths')
    sizes = [p.size for p in packets]
    timestamps = sorted(p.timestamp for p in packets)
    iats = np.diff(timestamps)
    count = len(packets)
    probs = np.array(list(Counter(p.port for p in packets).values()), dtype=float) / count
    return [float(v) for v in (
        count, sum(sizes), timestamps[-1] - timestamps[0],
        np.mean(iats) if len(iats) else 0, len({p.port for p in packets}),
        len({p.dst for p in packets}), sum('S' in p.tcp_flags or p.syn for p in packets),
        np.mean(sizes), np.std(sizes) if count > 1 else 0,
        sum(p.protocol == 'tcp' for p in packets) / count,
        sum(p.protocol == 'udp' for p in packets) / count,
        sum(p.protocol == 'icmp' for p in packets) / count,
        np.std(iats) if len(iats) > 1 else 0,
        -np.sum(probs * np.log2(probs + 1e-9))) ]
