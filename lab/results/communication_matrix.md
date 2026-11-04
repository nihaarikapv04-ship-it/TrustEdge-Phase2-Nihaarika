| Path | Src | Dst | Proto | Via firewall datapath | Result | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| firewall → webserver | trustedge-lab-firewall (172.21.0.2) | 172.21.0.10:80 | TCP/HTTP | NO (ordinary) | 200 | curl from firewall on wan network |
| firewall → wan-sink | firewall 172.21.0.2 | 172.21.0.11:80 /ping | TCP/HTTP | NO (ordinary) | 200 | curl |
| firewall DNS resolve aliases | firewall | webserver/wan-sink/dns/laptop names | Docker DNS | NO (ordinary) | 172.21.0.10     webserver;172.21.0.11     wan-sink;172.21.0.12     dns;172.20.0.10     laptop; | getent hosts |
| trustedge-lab-laptop → WAN HTTP via TrustEdge | trustedge-lab-laptop (172.20.0.10) | 172.21.0.10 or .11 :80 | TCP/HTTP | YES | PASS_PATH | 10:43:01.003336 IP 172.20.0.10.47300 > 172.21.0.10.80: Flags |
| trustedge-lab-laptop → DNS 172.21.0.12 | 172.20.0.10 | 172.21.0.12:53 | UDP/DNS | YES | PASS | resp 95 172.21.0.12 |
| trustedge-lab-iot-camera → WAN HTTP via TrustEdge | trustedge-lab-iot-camera (172.20.0.11) | 172.21.0.10 or .11 :80 | TCP/HTTP | YES | PASS_PATH | 10:43:14.493974 IP 172.20.0.11.57042 > 172.21.0.11.80: Flags |
| trustedge-lab-iot-camera → DNS 172.21.0.12 | 172.20.0.11 | 172.21.0.12:53 | UDP/DNS | YES | PASS | resp 95 172.21.0.12 |
| trustedge-lab-iot-thermostat → WAN HTTP via TrustEdge | trustedge-lab-iot-thermostat (172.20.0.1 | 172.21.0.10 or .11 :80 | TCP/HTTP | YES | PASS_PATH | 10:43:27.706714 IP 172.20.0.12.41610 > 172.21.0.11.80: Flags |
| trustedge-lab-iot-thermostat → DNS 172.21.0.12 | 172.20.0.12 | 172.21.0.12:53 | UDP/DNS | YES | PASS | resp 95 172.21.0.12 |
| trustedge-lab-phone → WAN HTTP via TrustEdge | trustedge-lab-phone (172.20.0.13) | 172.21.0.10 or .11 :80 | TCP/HTTP | YES | PASS_PATH | 10:43:36.613922 ARP, Request who-has 172.20.0.2 tell 172.20. |
| trustedge-lab-phone → DNS 172.21.0.12 | 172.20.0.13 | 172.21.0.12:53 | UDP/DNS | YES | PASS | resp 95 172.21.0.12 |
| trustedge-lab-printer → WAN HTTP via TrustEdge | trustedge-lab-printer (172.20.0.14) | 172.21.0.10 or .11 :80 | TCP/HTTP | YES | PASS_PATH | 10:43:50.332412 IP 172.20.0.14.39736 > 172.21.0.11.80: Flags |
| trustedge-lab-printer → DNS 172.21.0.12 | 172.20.0.14 | 172.21.0.12:53 | UDP/DNS | YES | PASS | resp 95 172.21.0.12 |
| laptop localhost ≠ webserver | laptop | 127.0.0.1:80 | TCP/HTTP | NO (ordinary) | FAIL_AS_DESIGNED | negative test |
| QUARANTINE laptop HTTP blocked; TRUSTED thermo allowed | isolation | WAN :80 | TCP/HTTP | YES | PASS | laptop HTTP 000; thermo HTTP 200; camera after release CAUTI |
