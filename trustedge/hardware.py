"""Pi deployment rendering and read-only preflight. Does not install host files."""
import argparse
import json
import platform
from pathlib import Path
import shutil
import subprocess
from .config import PiConfig
from .policy import NftPolicy


def render(config):
    """Return reviewable host artifacts without touching the host network."""
    policy = NftPolicy(config.lan, config.subnet, config.gateway, wan=config.wan)
    # Empty registry is the bootstrap policy: DHCP/local DNS only, forwarding denied.
    bootstrap = policy.render({})
    nat = ['add table ip trustedge_nat', 'delete table ip trustedge_nat']
    if config.masquerade:
        nat += ['table ip trustedge_nat {',
                'chain postrouting { type nat hook postrouting priority srcnat; policy accept;',
                f'ip saddr {config.subnet} oifname "{config.wan}" masquerade', '}', '}']
    dns = [f'interface={config.lan}', 'bind-dynamic', 'no-resolv', 'domain-needed', 'bogus-priv',
           'domain=trustedge.home.arpa', 'local=/trustedge.home.arpa/',
           f'dhcp-range={config.dhcp_start},{config.dhcp_end},{config.subnet_mask},12h',
           f'dhcp-option=option:router,{config.gateway}',
           f'dhcp-option=option:dns-server,{config.gateway}',
           'dhcp-authoritative']
    dns += [f'server={server}' for server in config.dns_upstream]
    dns += [f'dhcp-host={r["mac"]},{r["ip"]}' for r in config.reservations]
    nm = f'''[connection]
id=trustedge-lan
type=ethernet
interface-name={config.lan}
autoconnect=true

[ipv4]
method=manual
address1={config.lan_address}
never-default=true
ignore-auto-dns=true

[ipv6]
method=disabled
'''
    network_service = '''[Unit]
Description=TrustEdge bootstrap firewall and IPv4 forwarding
After=network-online.target nftables.service
Wants=network-online.target
Requires=nftables.service
Before=trustedge.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/trustedge/bootstrap.nft
ExecStart=/usr/sbin/nft -f /etc/trustedge/nat.nft
ExecStart=/usr/sbin/sysctl -w net.ipv4.ip_forward=1
ExecStop=/usr/sbin/sysctl -w net.ipv4.ip_forward=0

[Install]
WantedBy=multi-user.target
'''
    app_service = '''[Unit]
Description=TrustEdge local Pi gateway
After=trustedge-network.service dnsmasq.service
Requires=trustedge-network.service dnsmasq.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/trustedge
EnvironmentFile=/etc/trustedge.env
ExecStartPre=/opt/trustedge/.venv/bin/python -m trustedge.hardware check --config /etc/trustedge/gateway.json
ExecStart=/opt/trustedge/.venv/bin/python -m trustedge --config /etc/trustedge/gateway.json
Restart=on-failure
RestartSec=5
StateDirectory=trustedge
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/trustedge
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
'''
    return {'gateway.json': json.dumps(config.to_dict(), indent=2)+'\n',
            'bootstrap.nft': bootstrap, 'nat.nft': '\n'.join(nat)+'\n',
            'trustedge-lan.nmconnection': nm, 'dnsmasq-trustedge.conf': '\n'.join(dns)+'\n',
            'trustedge-network.service': network_service, 'trustedge.service': app_service,
            # Dedicated appliance: forwarding is off until bootstrap rules load.
            '90-trustedge.conf': 'net.ipv4.ip_forward=0\n'}


def preflight(config, runner=subprocess.run, system=None, which=shutil.which):
    """Report host readiness using only local commands; never probe Internet sites."""
    issues = []
    if (system or platform.system()) != 'Linux':
        return ['live deployment requires Linux (Raspberry Pi OS recommended)']
    for command in ('ip', 'nft', 'sysctl', 'dnsmasq'):
        if not which(command):
            issues.append(f'missing command: {command}')
    if issues:
        return issues
    def run(args):
        result = runner(args, capture_output=True, text=True, timeout=10, check=False)
        if result.returncode:
            raise ValueError(result.stderr.strip() or 'command failed: ' + ' '.join(args))
        return result.stdout
    try:
        links = {link['ifname']: link for link in json.loads(run(['ip', '-j', 'link', 'show']))}
        for name in (config.lan, config.wan):
            if name not in links:
                issues.append(f'interface not found: {name}')
            elif 'UP' not in links[name].get('flags', []):
                issues.append(f'interface is down: {name}')
        addresses = json.loads(run(['ip', '-j', '-4', 'address', 'show']))
        lan_addresses = [f"{a['local']}/{a['prefixlen']}" for link in addresses
                         if link['ifname'] == config.lan for a in link.get('addr_info', [])]
        if config.lan_address not in lan_addresses:
            issues.append(f'{config.lan} must have {config.lan_address}')
        from ipaddress import IPv4Interface
        for link in addresses:
            if link['ifname'] != config.wan:
                continue
            for addr in link.get('addr_info', []):
                if IPv4Interface(f"{addr['local']}/{addr['prefixlen']}").network.overlaps(IPv4Interface(config.lan_address).network):
                    issues.append('WAN and IoT LAN subnets overlap')
        routes = json.loads(run(['ip', '-j', '-4', 'route', 'show', 'default']))
        if not any(route.get('dev') == config.wan for route in routes):
            issues.append(f'no IPv4 default route on {config.wan}')
        if run(['sysctl', '-n', 'net.ipv4.ip_forward']).strip() != '1':
            issues.append('IPv4 forwarding is disabled; start trustedge-network.service first')
        # Validate grammar/permissions without replacing current rules.
        result = runner(['nft', '--check', '-f', '-'], input=render(config)['bootstrap.nft'],
                        capture_output=True, text=True, timeout=10, check=False)
        if result.returncode:
            issues.append('nftables validation failed: ' + result.stderr.strip())
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        issues.append(str(exc))
    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['render', 'check'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--output')
    args = parser.parse_args()
    config = PiConfig.load(args.config)
    if args.action == 'render':
        if not args.output:
            parser.error('render requires --output')
        directory = Path(args.output)
        directory.mkdir(parents=True, exist_ok=True)
        for name, content in render(config).items():
            target = directory / name
            if target.exists():
                raise FileExistsError(f'refusing to overwrite {target}')
        for name, content in render(config).items():
            (directory / name).write_text(content)
        print(f'Rendered deployment files to {directory}; no host configuration changed')
    else:
        issues = preflight(config)
        print(json.dumps({'ready': not issues, 'issues': issues}, indent=2))
        if issues:
            raise SystemExit(1)

if __name__ == '__main__':
    main()
