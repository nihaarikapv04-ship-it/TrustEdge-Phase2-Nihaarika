"""One owned nftables table, replaced in a single atomic kernel transaction."""
import re
import subprocess
from .registry import ipv4

class PolicyError(RuntimeError):
    pass

class SimulationPolicy:
    def apply(self, devices):
        return {'table': 'simulation', 'device_count': len(devices), 'verified': True}

class NftPolicy:
    def __init__(self, lan, subnet, dns, runner=subprocess.run, wan=None, api_port=8080):
        from ipaddress import IPv4Network
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', lan):
            raise ValueError('invalid LAN interface')
        if not isinstance(api_port, int) or isinstance(api_port, bool) or not 1 <= api_port <= 65535:
            raise ValueError('invalid API port')
        self.lan, self.subnet, self.dns = lan, str(IPv4Network(subnet)), ipv4(dns)
        if wan is not None and (not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', wan) or wan == lan):
            raise ValueError('WAN must be a valid interface different from LAN')
        self.wan = wan
        self.api_port = api_port
        self.runner = runner

    def validate_device(self, device):
        from ipaddress import IPv4Address, IPv4Network
        network = IPv4Network(self.subnet)
        address = IPv4Address(device['ip'])
        if address not in network or address in (network.network_address, network.broadcast_address, IPv4Address(self.dns)):
            raise ValueError('device IP must be a usable LAN address distinct from the gateway/DNS')

    def render(self, devices):
        # Accept the management API before the LAN input drop. A separate table's
        # accept does not stop a later drop in this table (nftables tables are independent).
        lines = ['add table inet trustedge', 'delete table inet trustedge', 'table inet trustedge {',
                 f'chain input {{ type filter hook input priority -10; policy accept;',
                 f'tcp dport {self.api_port} accept',
                 f'iifname "{self.lan}" meta nfproto ipv6 drop',
                 f'iifname "{self.lan}" udp sport 68 udp dport 67 accept',
                 f'iifname "{self.lan}" ip daddr {self.dns} udp dport 53 limit rate 10/minute accept',
                 f'iifname "{self.lan}" ip daddr {self.dns} tcp dport 53 limit rate 10/minute accept',
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
            elif tier == 'CAUTIOUS':
                # Phase 1 apply_policy CAUTIOUS: UDP/53 rate-limited 10/min, then HTTP(S), else DROP.
                lines.append(f'{source} ip daddr {self.dns} udp dport 53 limit rate 10/minute accept')
                lines.append(f'{reply} ip saddr {self.dns} udp sport 53 ct state established accept')
                for dst in device['destinations']:
                    dst = ipv4(dst)
                    lines += [f'{source} ip daddr {dst} tcp dport {{ 80, 443 }} limit rate 50/second accept',
                              f'{reply} ip saddr {dst} tcp sport {{ 80, 443 }} ct state established accept']
                lines += [f'{source} drop', f'{reply} drop']
            elif tier == 'QUARANTINE':
                # Phase 1 apply_policy QUARANTINE: unrestricted UDP/53 only, then DROP.
                lines.append(f'{source} ip daddr {self.dns} udp dport 53 accept')
                lines.append(f'{reply} ip saddr {self.dns} udp sport 53 ct state established accept')
                lines += [f'{source} drop', f'{reply} drop']
            else:
                raise ValueError('invalid tier')
        lines += [f'iifname "{self.lan}" drop', f'oifname "{self.lan}" drop', '}', '}']
        return '\n'.join(lines) + '\n'

    def apply(self, devices):
        rendered = self.render(devices)
        try:
            result = self.runner(['nft', '-f', '-'], input=rendered, text=True,
                                 capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PolicyError(str(exc)) from exc
        if result.returncode != 0:
            raise PolicyError(result.stderr.strip() or 'nftables transaction failed')
        # Read-back confirms the owned table exists after the atomic replace.
        # Fail closed so applied_tier is not advanced on a silent no-op apply.
        try:
            check = self.runner(
                ['nft', '-j', 'list', 'table', 'inet', 'trustedge'],
                capture_output=True, text=True, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PolicyError(f'nftables verify failed: {exc}') from exc
        if check.returncode != 0:
            raise PolicyError(
                check.stderr.strip() or 'nftables verify failed: inet trustedge missing')
        return {
            'table': 'inet trustedge',
            'device_count': len(devices),
            'rule_lines': rendered.count('\n'),
            'verified': True,
        }
