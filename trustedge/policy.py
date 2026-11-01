"""One owned nftables table, replaced in a single atomic kernel transaction."""
import re
import subprocess
from .registry import ipv4

class PolicyError(RuntimeError):
    pass

class SimulationPolicy:
    def apply(self, devices):
        return None

class NftPolicy:
    def __init__(self, lan, subnet, dns, runner=subprocess.run, wan=None):
        from ipaddress import IPv4Network
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', lan):
            raise ValueError('invalid LAN interface')
        self.lan, self.subnet, self.dns = lan, str(IPv4Network(subnet)), ipv4(dns)
        if wan is not None and (not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', wan) or wan == lan):
            raise ValueError('WAN must be a valid interface different from LAN')
        self.wan = wan
        self.runner = runner

    def validate_device(self, device):
        from ipaddress import IPv4Address, IPv4Network
        network = IPv4Network(self.subnet)
        address = IPv4Address(device['ip'])
        if address not in network or address in (network.network_address, network.broadcast_address, IPv4Address(self.dns)):
            raise ValueError('device IP must be a usable LAN address distinct from the gateway/DNS')

    def render(self, devices):
        lines = ['add table inet trustedge', 'delete table inet trustedge', 'table inet trustedge {',
                 f'chain input {{ type filter hook input priority -10; policy accept;',
                 f'iifname "{self.lan}" meta nfproto ipv6 drop',
                 f'iifname "{self.lan}" udp sport 68 udp dport 67 accept',
                 f'iifname "{self.lan}" ip daddr {self.dns} udp dport 53 limit rate 10/second accept',
                 f'iifname "{self.lan}" ip daddr {self.dns} tcp dport 53 limit rate 10/second accept',
                 f'iifname "{self.lan}" drop', '}',
                 'chain forward { type filter hook forward priority -10; policy accept;',
                 f'iifname "{self.lan}" meta nfproto ipv6 drop',
                 f'oifname "{self.lan}" meta nfproto ipv6 drop',
                 f'iifname "{self.lan}" ip saddr != {self.subnet} drop']
        # Restrictions precede any established-flow allowance, including on return traffic.
        for ip, device in sorted(devices.items()):
            self.validate_device(dict(device, ip=ip))
            ip = ipv4(ip)
            tier = device['desired_tier']
            outbound = f'oifname "{self.wan}" ' if self.wan else ''
            inbound = f'iifname "{self.wan}" ' if self.wan else ''
            source = f'iifname "{self.lan}" {outbound}ip saddr {ip}'
            reply = f'{inbound}oifname "{self.lan}" ip daddr {ip}'
            if tier == 'TRUSTED':
                lines += [f'{source} accept', f'{reply} ct state established,related accept']
            elif tier in ('CAUTIOUS', 'QUARANTINE'):
                for proto in ('udp', 'tcp'):
                    lines.append(f'{source} ip daddr {self.dns} {proto} dport 53 limit rate 10/second accept')
                    lines.append(f'{reply} ip saddr {self.dns} {proto} sport 53 ct state established accept')
                if tier == 'CAUTIOUS':
                    for dst in device['destinations']:
                        dst = ipv4(dst)
                        lines += [f'{source} ip daddr {dst} tcp dport {{ 80, 443 }} limit rate 50/second accept',
                                  f'{reply} ip saddr {dst} tcp sport {{ 80, 443 }} ct state established accept']
                lines += [f'{source} drop', f'{reply} drop']
            else:
                raise ValueError('invalid tier')
        lines += [f'iifname "{self.lan}" drop', f'oifname "{self.lan}" drop', '}', '}']
        return '\n'.join(lines) + '\n'

    def apply(self, devices):
        try:
            result = self.runner(['nft', '-f', '-'], input=self.render(devices), text=True,
                                 capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PolicyError(str(exc)) from exc
        if result.returncode != 0:
            raise PolicyError(result.stderr.strip() or 'nftables transaction failed')
