"""Validated configuration for a dedicated, routed Raspberry Pi gateway."""
from dataclasses import asdict, dataclass, fields
from ipaddress import IPv4Address, IPv4Interface
import json
from pathlib import Path
import re

@dataclass(frozen=True)
class PiConfig:
    lan: str = 'eth1'
    wan: str = 'eth0'
    lan_address: str = '192.168.50.1/24'
    dhcp_start: str = '192.168.50.100'
    dhcp_end: str = '192.168.50.200'
    dns_upstream: tuple = ()
    reservations: tuple = ()
    database: str = '/var/lib/trustedge/live.sqlite'
    api_port: int = 8080
    masquerade: bool = True

    def __post_init__(self):
        for interface in (self.lan, self.wan):
            if not isinstance(interface, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface):
                raise ValueError('invalid interface name')
        if self.lan == self.wan:
            raise ValueError('LAN and WAN must be different interfaces')
        lan = IPv4Interface(self.lan_address)
        if lan.network.prefixlen > 30 or lan.ip in (lan.network.network_address, lan.network.broadcast_address):
            raise ValueError('LAN address must be a usable address in a subnet of at least /30')
        first, last = IPv4Address(self.dhcp_start), IPv4Address(self.dhcp_end)
        if not (lan.network.network_address < first <= last < lan.network.broadcast_address) or first <= lan.ip <= last:
            raise ValueError('DHCP pool must be inside LAN and exclude the gateway')
        if not isinstance(self.dns_upstream, (tuple, list)):
            raise ValueError('dns_upstream must be a list of IPv4 addresses')
        for server in self.dns_upstream:
            address = IPv4Address(server)
            if address in lan.network or address.is_multicast or address.is_unspecified:
                raise ValueError('upstream DNS must be outside the IoT LAN')
        if not isinstance(self.reservations, (tuple, list)):
            raise ValueError('reservations must be a list')
        seen_ip, seen_mac = set(), set()
        for reservation in self.reservations:
            if not isinstance(reservation, dict) or set(reservation) != {'mac', 'ip'}:
                raise ValueError('each reservation requires only mac and ip')
            mac, address = reservation['mac'], IPv4Address(reservation['ip'])
            if not isinstance(mac, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
                raise ValueError('invalid reservation MAC')
            if not self.usable_device(address) or address in seen_ip or mac.lower() in seen_mac:
                raise ValueError('invalid or duplicate reservation')
            seen_ip.add(address)
            seen_mac.add(mac.lower())
        if not isinstance(self.api_port, int) or isinstance(self.api_port, bool) or not 1024 <= self.api_port <= 65535:
            raise ValueError('API port must be in 1024..65535')
        if not isinstance(self.masquerade, bool):
            raise ValueError('masquerade must be boolean')
        if not isinstance(self.database, str) or not re.fullmatch(r'/var/lib/trustedge/[A-Za-z0-9_.-]+\.sqlite', self.database):
            raise ValueError('hardware database must be a .sqlite file directly in /var/lib/trustedge')

    @property
    def gateway(self):
        return str(IPv4Interface(self.lan_address).ip)

    @property
    def subnet(self):
        return str(IPv4Interface(self.lan_address).network)

    @property
    def subnet_mask(self):
        return str(IPv4Interface(self.lan_address).network.netmask)

    def usable_device(self, address):
        address = IPv4Address(address)
        net = IPv4Interface(self.lan_address).network
        return address in net and address not in (net.network_address, net.broadcast_address, IPv4Address(self.gateway))

    def to_dict(self):
        return asdict(self)

    @classmethod
    def load(cls, path):
        data = json.loads(Path(path).read_text())
        if not isinstance(data, dict) or set(data) - {f.name for f in fields(cls)}:
            raise ValueError('configuration contains unknown keys or is not an object')
        return cls(**data)
