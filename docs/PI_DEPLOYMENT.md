# Future Raspberry Pi deployment

These instructions are for the friend continuing on real hardware. No host setup is performed by the generator, and the current development work does not require hardware.

## Proposed physical topology

Available hardware: Raspberry Pi 4, one router, three Ethernet cables, USB-to-Ethernet adapter. Use Raspberry Pi OS Lite **64-bit** with Python 3.11 / Debian Bookworm-compatible packages as the reference environment.

```text
Existing router LAN port
       | Ethernet cable (WAN uplink)
Pi built-in Ethernet (example eth0)
       Pi 4: capture → IF/AE → trust → nftables; SQLite on Pi
Pi USB-to-Ethernet adapter (example eth1, possibly enx...)
       | Ethernet cable (isolated IoT LAN)
One wired test laptop/device
```

The third cable is spare for initial testing. Multiple wired clients need a switch behind the USB adapter. Do not connect test clients to the upstream router's other LAN/Wi-Fi interfaces: that bypasses the Pi. A Wi-Fi AP behind the Pi is an optional later topology; this implementation does not configure hostapd or bridge mode. Keep a console or upstream-side SSH connection for administration because IoT-side gateway access is restricted to DHCP/DNS.

## Prepare configuration without hardware

Copy `deploy/pi.example.json` to a personal configuration file. The configuration includes:

- Different LAN/WAN interface names, LAN address and DHCP pool. Use `ip -br link` on the Pi to find actual names.
- A LAN subnet that does not overlap the router's network. The example uses `192.168.50.0/24`.
- `dns_upstream: []` for local-only names. To resolve external names, explicitly add your router/resolver IPv4 address. These are ordinary device DNS requests, not telemetry; no public resolver is hardcoded and `/etc/resolv.conf` is not consumed by dnsmasq.
- Optional `reservations: [{"mac":"02:00:00:00:00:02","ip":"192.168.50.2"}]`. Reservations provide stable IP identity; they do not enroll a device or stop MAC/IP spoofing.
- `masquerade: true` for the normal router setup. Disable it only when the upstream router has an explicit return route to the IoT subnet.

```sh
.venv/bin/python -m trustedge.hardware render \
  --config deploy/pi.example.json --output build/my-pi
```

The generator validates configuration and emits reviewable files. It refuses to overwrite existing output and performs no `sudo`, package installation, service activation or network changes.

## Install when the Pi is available

Use a dedicated Pi gateway; the forwarding setting is system-wide. Review existing NetworkManager, nftables and DNS services before installing. Do not overwrite unrelated firewall rules or enable competing DHCP servers on the same LAN.

1. Provision OS packages `python3`, `python3-venv`, `nftables`, `iproute2`, `util-linux`, `dnsmasq` and `libpcap0.8` (package name can vary with OS). Scapy's `ip` capture filter requires working libpcap. Install Python dependencies in `/opt/trustedge/.venv` from this project; no dependencies/models are downloaded by the running service. An offline wheelhouse may be used during provisioning.
2. Copy the source to `/opt/trustedge`. Render artifacts from the reviewed hardware configuration. Copy `gateway.json`, `bootstrap.nft`, and `nat.nft` into `/etc/trustedge/`.
3. Install `trustedge-lan.nmconnection` into `/etc/NetworkManager/system-connections/` with root ownership and mode `0600`; load it with `nmcli connection load <path>` and activate `trustedge-lan`. Disable any conflicting auto-connect profile on the USB adapter. The generated profile is manual IPv4, not NetworkManager shared mode; NAT/DHCP are owned explicitly. Leave the existing WAN connection unchanged.
4. Install `dnsmasq-trustedge.conf` as `/etc/dnsmasq.d/trustedge.conf`. Check it with `dnsmasq --test`, then restart dnsmasq. Check that the OS package actually reads `/etc/dnsmasq.d/`. Only this isolated LAN should receive its DHCP leases.
5. Install `90-trustedge.conf` into `/etc/sysctl.d/`. Remove conflicting forwarding-on configuration for this dedicated gateway. Include `/etc/trustedge/bootstrap.nft` from the existing `/etc/nftables.conf` so nftables also denies forwarding early in boot. Do not replace the entire existing nftables file. Load the reviewed bootstrap before enabling forwarding; it initially allows only local DNS/DHCP from the IoT LAN.
6. Install `trustedge-network.service` and `trustedge.service` into `/etc/systemd/system/`. Network startup checks each nft command, installs bootstrap then NAT, and enables IPv4 forwarding last. Failure stops startup before the application is launched. The service never flushes the global ruleset; its tables are `inet trustedge` and `ip trustedge_nat`.
7. Write `/etc/trustedge.env` with a strong `TRUSTEDGE_API_TOKEN=...`, owned by root with mode `0600`. Generate a token locally, for example `python3 -c 'import secrets; print(secrets.token_hex(24))'`. Do not store it in the repository.
8. Run `systemctl daemon-reload`, enable `nftables.service`, then `systemctl enable --now trustedge-network.service trustedge.service`. The application unit requires both the network bootstrap and dnsmasq. Inspect `journalctl -u trustedge-network -u trustedge` if startup fails.
9. Enroll the reserved device IP via the loopback API. Enrollment starts CAUTIOUS and does not grant broad Internet access. Configure expected destinations explicitly. Run the acceptance checklist below before adding more clients.

Generated `trustedge.service` executes:

```sh
/opt/trustedge/.venv/bin/python -m trustedge.hardware check --config /etc/trustedge/gateway.json
/opt/trustedge/.venv/bin/python -m trustedge --config /etc/trustedge/gateway.json
```

The first command is read-only preflight: Linux/tools, interface state, LAN address, subnet overlap, WAN default route, forwarding state, and `nft --check`. It does not contact external hosts, install rules, or change routes. It does not prove the upstream router or physical cabling works; validate those separately. The application validates its SQLite/model state and applies saved policy before capture/API startup.

Stopping the application preserves its last kernel policy. Stopping `trustedge-network.service` disables global IPv4 forwarding. Do not use additional firewall/flow-offload services that bypass or overwrite these tables. If changing subnets, migrate/re-enroll stored device addresses deliberately; incompatible existing devices must not silently regain access.

## Acceptance tests for the friend

First run the ordinary suite. Then, on Linux with the required capabilities/tools:

```sh
sudo env TRUSTEDGE_NFT_TESTS=1 .venv/bin/python -m unittest discover \
  -s tests -p test_nft_linux.py -v
```

These tests use disposable network namespaces; they do not edit host interfaces/rules. The packet test exercises actual TCP/UDP through a virtual routed gateway with NAT, explicit destination restrictions, local DNS/DHCP ports, failed transaction rollback, an existing TCP flow during quarantine, SQLite restart recovery and deletion. DNS/DHCP test servers are protocol-neutral echo fixtures that prove port reachability; they are not full DNS or DHCP protocol validation. The bootstrap test emulates rule reloading, not a physical power cycle. The tests have not been executed on the macOS development host.

On the physical Pi, additionally record:

- Client gets the intended lease, Pi default gateway and local DNS; real DNS queries and DHCP renewal work.
- Unknown/deleted clients cannot forward; CAUTIOUS permits only configured destinations; TRUSTED works; quarantine cuts off existing connections except configured DNS/local DHCP.
- IPv6 cannot bypass the policy. Upstream router ports/Wi-Fi do not offer test clients an alternate path.
- Capture produces the exact 14-feature contract, with no packet payload persistence or synthetic fallback; drop counters stay acceptable under load.
- Service restart and actual Pi reboot preserve trust, signature thresholds, baseline/model state and tiers; traffic stays denied before bootstrap recovery.
- Failure to load/apply nft rules or models is visible and never reported as successful enforcement.
- No telemetry/model-fetch/SMTP connections occur. Normal forwarded client traffic and explicitly configured DNS are expected.

References for reviewing generated artifacts: [NetworkManager keyfiles](https://networkmanager.dev/docs/api/latest/nm-settings-keyfile.html), [dnsmasq manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html), and [systemd service ordering](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).
