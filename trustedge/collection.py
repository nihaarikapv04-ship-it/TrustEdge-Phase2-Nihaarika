"""Live Scapy metadata capture matching Phase 1. Never falls back to simulation."""
import threading
import time
from collections import defaultdict
from .features import Packet
from .policy import PolicyError
from .detection import DetectionError


def packet_metadata(packet):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    # Some Docker/veth paths deliver ETH_P_ALL frames as unbound Raw (no Ether/IP
    # layers). Re-dissect as Ethernet so Phase 1 feature extraction still runs.
    if not packet.haslayer(IP):
        try:
            packet = Ether(bytes(packet))
        except Exception:
            return None
    if not packet.haslayer(IP):
        return None
    ip = packet[IP]
    transport = packet[TCP] if packet.haslayer(TCP) else packet[UDP] if packet.haslayer(UDP) else None
    flags = str(packet[TCP].flags) if packet.haslayer(TCP) else ''
    return Packet(ip.src, ip.dst, len(packet), {6: 'tcp', 17: 'udp', 1: 'icmp'}.get(ip.proto, 'other'),
                  transport.dport if transport else 0, 'S' in flags,
                  timestamp=time.time(), sport=transport.sport if transport else 0, tcp_flags=flags)


class LiveCollector:
    def __init__(self, gateway, interface, seconds=60):
        self.gateway, self.interface, self.seconds = gateway, interface, seconds
        self.stop_event = threading.Event()
        self.sniffer = None
        self.error = None
        self.buffers = defaultdict(list)
        self.buffer_lock = threading.Lock()
        self.dropped = 0

    @property
    def running(self):
        return bool(self.sniffer and self.sniffer.running and
                    getattr(self, 'worker', None) and self.worker.is_alive())

    def start(self):
        from scapy.sendrecv import AsyncSniffer
        started = threading.Event()
        # Prefer an explicit L4 filter: bare BPF 'ip' matches nothing on some
        # Docker Desktop / veth setups, while 'tcp or udp or icmp' captures traffic.
        self.sniffer = AsyncSniffer(iface=self.interface, filter='tcp or udp or icmp', store=False,
                                    prn=self._packet, started_callback=started.set)
        self.sniffer.start()
        if not started.wait(5):
            self.error = str(getattr(self.sniffer, 'exception', 'capture failed to start'))
            raise RuntimeError(self.error)
        self.worker = threading.Thread(target=self._windows, daemon=True)
        self.worker.start()

    def _packet(self, raw):
        packet = packet_metadata(raw)
        if packet is None:
            return
        with self.gateway.lock:
            device = self.gateway.storage.devices().get(packet.src)
            if not device or device.get('deleting'):
                return
            key = (packet.src, (device['epoch'], device['generation']))
        with self.buffer_lock:
            if len(self.buffers[key]) < 100000:
                self.buffers[key].append(packet)
            else:
                self.dropped += 1

    def _windows(self):
        while not self.stop_event.wait(self.seconds):
            if not self.sniffer.running:
                self.error = 'capture stopped; live detection unavailable'
                return
            with self.buffer_lock:
                batch, self.buffers = self.buffers, defaultdict(list)
            try:
                for (ip, identity), packets in batch.items():
                    try:
                        self.gateway.window(ip, packets, self.seconds, identity)
                    except (PolicyError, DetectionError, KeyError):
                        continue  # Service records failures; deleted windows cannot re-enroll.
            except Exception as exc:
                self.error = str(exc)
                return

    def stop(self):
        self.stop_event.set()
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
        worker = getattr(self, 'worker', None)
        if worker:
            worker.join(timeout=15)
