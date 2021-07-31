
#====================================================================================================================
# File:        packet_generator.py
# Case:        VUT, FIT, IPK, project 2
# Date:        24. 4. 2021
# Author:      David Mihola
# Contact:     xmihol00@stud.fit.vutbr.cz
# Interpreted: Python 3.8   
# Description: IP version 4, IP version 6 and ARP packet generator creating TCP, UDP and ICMP transport protocols.
#====================================================================================================================

import string
import random
import scapy.all as sc
import scapy.layers.inet as lr
import scapy.layers.inet6 as lr6
import scapy.layers.l2 as l2
import scapy.layers.ipsec as ips

TCP_header_code = 6
UDP_header_code = 17
ICMP_header_code = 1
IPv6_fragment_ext = 44
IPv6_destination_ext = 60
IPv6_routing_ext = 43

IPv4 = lr.IP(src="123.123.123.123", dst="185.51.241.138")
IPv6 = lr6.IPv6(src="ff02::16", dst="fe80::8ac:68e9:d469:d421")
iff, _, _ = sc.conf.route6.route("fe80::8ac:68e9:d469:d421")

UDP = lr.UDP(dport=65000, sport=854)
TCP = lr.TCP(dport=6, sport=854)
ICMP = lr.ICMP()
ICMPv6EchoRequest = lr6.ICMPv6EchoRequest()
ICMPv6DestUnreach = lr6.ICMPv6DestUnreach()
ICMPv6MLQuery = lr6.ICMPv6MLQuery()
ICMPv6NDOptDNSSL = lr6.ICMPv6NDOptDNSSL()
ICMPv6 = lr6.ICMPv6EchoReply()
ARP = l2.ARP()

payload = ''.join(random.choices(string.digits + string.ascii_letters, k = 20)) + "xmihol00"

print("v4 + TCP")
i = 0
while i < 4:
    sc.send(IPv4/lr.TCP(dport=65004)/payload)
    i += 1
input("press ENTER to continue...")

print("v6 + TCP")
i = 0
while i < 4:
    sc.send(IPv6/lr.TCP(dport=65006)/payload)
    i += 1
input("press ENTER to continue...")

print("v4 + UDP")
sc.send(IPv4/lr.UDP(dport=65104)/payload)
input("press ENTER to continue...")

print("v6 + UDP")
sc.send(IPv6/lr.UDP(dport=65106)/payload)
input("press ENTER to continue...")

print("v4 + ICMP")
i = 0
while i < 4:
    sc.send(IPv4/ICMP/payload)
    i += 1
input("press ENTER to continue...")

print("v6 + ICMP")
i = 0
while i < 4:
    sc.send(IPv6/ICMPv6/payload)
    i += 1
input("press ENTER to continue...")

print("ARP")
i = 0
while i < 4:
    sc.send(ARP/payload)
    i += 1
input("press ENTER to continue...")

sc.send(IPv4/lr.TCP(dport=65004)/payload)
sc.send(IPv4/lr.UDP(dport=65004)/payload)
sc.send(IPv4/ICMP/payload)
sc.send(IPv6/ICMPv6/payload)
sc.send(ARP/payload)

exit(0)
res = input("press ENTER to stop or c to continue...")
if res != "c":
    exit(0)


IPv6HopByHopTCP = lr6.IPv6ExtHdrHopByHop(nh=TCP_header_code)
IPv6RoutingTCP = lr6.IPv6ExtHdrRouting(nh=TCP_header_code)
IPv6FragmentTCP = lr6.IPv6ExtHdrFragment(nh=TCP_header_code)
IPv6DestinationTCP = lr6.IPv6ExtHdrDestOpt(nh=TCP_header_code)

AuthenticationTCP = ips.AH(nh=TCP_header_code, payloadlen=1)
ESP = ips.ESP()

IPv6HopByHopUDP = lr6.IPv6ExtHdrHopByHop(nh=UDP_header_code)
IPv6RoutingUDP = lr6.IPv6ExtHdrRouting(nh=UDP_header_code)
IPv6FragmentUDP = lr6.IPv6ExtHdrFragment(nh=UDP_header_code)
IPv6DestinationUDP = lr6.IPv6ExtHdrDestOpt(nh=UDP_header_code)

AuthenticationUDP = ips.AH(nh=UDP_header_code, payloadlen=1)

IPv6HopByHopICMP = lr6.IPv6ExtHdrHopByHop(nh=ICMP_header_code)
IPv6RoutingICMP = lr6.IPv6ExtHdrRouting(nh=ICMP_header_code)
IPv6FragmentICMP = lr6.IPv6ExtHdrFragment(nh=ICMP_header_code)
IPv6DestinationICMP = lr6.IPv6ExtHdrDestOpt(nh=ICMP_header_code)

AuthenticationICMP = ips.AH(nh=ICMP_header_code)

IPv6HopByHopToRouting = lr6.IPv6ExtHdrHopByHop(nh=IPv6_routing_ext)
IPv6HopByHopToDestination = lr6.IPv6ExtHdrHopByHop(nh=IPv6_destination_ext)
IPv6HopByHopToFragment = lr6.IPv6ExtHdrHopByHop(nh=IPv6_fragment_ext)
IPv6RoutingToFragment = lr6.IPv6ExtHdrRouting(nh=IPv6_fragment_ext)
IPv6DestinationToFragment = lr6.IPv6ExtHdrDestOpt(nh=IPv6_fragment_ext)
IPv6FragmentToDestination = lr6.IPv6ExtHdrFragment(nh=IPv6_destination_ext)

IPv6HopByHopOptionsTCP = lr6.IPv6ExtHdrHopByHop(nh=TCP_header_code, options=[lr6.HAO(), lr6.Jumbo(jumboplen=2**30)])
IPv6RoutingOptionsTCP = lr6.IPv6ExtHdrRouting(nh=TCP_header_code, addresses=["fe80::8ac:68e9:d469:d421", "aaab::8ac:68e9:d469:d421", "fe80::8ac:68e9:d469:ccda", "aaaa::aaaa"])
IPv6FragmentOffsetTCP = lr6.IPv6ExtHdrFragment(nh=TCP_header_code, offset=2)
IPv6DestinationOptionsTCP = lr6.IPv6ExtHdrDestOpt(nh=TCP_header_code, options=[lr6.RouterAlert(), lr6.HAO(), lr6.HAO()])

AuthenticationPaylaodTCP = ips.AH(nh=TCP_header_code, payloadlen=3, icv=b'abcdefgh')

IPv6HopByHopOptionsUDP = lr6.IPv6ExtHdrHopByHop(nh=UDP_header_code, options=[lr6.HAO(), lr6.Jumbo(jumboplen=2**30)])
IPv6RoutingOptionsUDP = lr6.IPv6ExtHdrRouting(nh=UDP_header_code, addresses=["fe80::8ac:68e9:d469:d421", "aaab::8ac:68e9:d469:d421", "fe80::8ac:68e9:d469:ccda", "aaaa::aaaa"])
IPv6FragmentOffsetUDP = lr6.IPv6ExtHdrFragment(nh=UDP_header_code, offset=2)
IPv6DestinationOptionsUDP = lr6.IPv6ExtHdrDestOpt(nh=UDP_header_code, options=[lr6.RouterAlert(), lr6.HAO(), lr6.HAO()])

AuthenticationPaylaodUDP = ips.AH(nh=UDP_header_code, payloadlen=5, icv=b'abcdefghijklmnop')
AuthenticationPaylaodICMP = ips.AH(nh=ICMP_header_code, payloadlen=4, icv=b'abcdefghijkl')

IPv6HopByHopOptionsToRouting = lr6.IPv6ExtHdrHopByHop(nh=IPv6_routing_ext, options=[lr6.HAO(), lr6.Jumbo(jumboplen=2**30), lr6.RouterAlert()])
IPv6DestinationOptionsToRouting = lr6.IPv6ExtHdrDestOpt(nh=IPv6_routing_ext, options=[lr6.RouterAlert(), lr6.HAO(), lr6.HAO()])
IPv6RoutingOptionsToFragment = lr6.IPv6RoutingOptionsUDP = lr6.IPv6ExtHdrRouting(nh=IPv6_fragment_ext, addresses=["fe80::8ac:68e9:d469:d421", "aaab::8ac:68e9:d469:bbbb"])

# ARP protocol
sc.sendp(ARP/"TEST - ARP")

# IPv4 with TCP/UDP/ICMP protocols and extension headers with payload
sc.send(IPv4/AuthenticationPaylaodTCP/TCP/"TEST - IPv4 + Authentication extension header with payload + TCP")
sc.send(IPv4/AuthenticationPaylaodUDP/UDP/"TEST - IPv4 + Authentication extension header with payload + UDP")
sc.send(IPv4/AuthenticationPaylaodICMP/ICMP/"TEST - IPv4 + Authentication extension header with payload + ICMP")

# IPv4 with TCP/UDP/ICMP protocols and extension headers
sc.send(IPv4/AuthenticationTCP/TCP/"TEST - IPv4 + Authentication extension header  + TCP")
sc.send(IPv4/AuthenticationUDP/UDP/"TEST - IPv4 + Authentication extension header  + UDP")
sc.send(IPv4/AuthenticationICMP/ICMP/"TEST - IPv4 + Authentication extension header + ICMP")

# IPv4 with TCP/UDP/ICMP protocols
sc.send(IPv4/TCP/"TEST - IPv4 + TCP")
sc.send(IPv4/UDP/"TEST - IPv4 + UDP")
sc.send(IPv4/ICMP/"TEST - IPv4 + ICMP")

# IPv4 with TCP/UDP/ICMP protocols without payload
sc.send(IPv4/TCP)
sc.send(IPv4/UDP)
sc.send(IPv4/ICMP)

# IPv6 with TCP and multiple extension headers with options
sc.send(IPv6/IPv6HopByHopOptionsToRouting/IPv6RoutingOptionsTCP/TCP/"TEST - IPv6 with Hop by Hop extension header and options and with Routing extension header and addresses + TCP")
sc.send(IPv6/IPv6DestinationOptionsToRouting/IPv6RoutingOptionsTCP/TCP/"TEST - IPv6 with Destination extension header and options and with Routing extension header and addresses + TCP")
sc.send(IPv6/IPv6RoutingOptionsToFragment/IPv6FragmentOffsetTCP/TCP/"TEST - IPv6 with Routing extension header and addresses and with Fragment extension header and offset + TCP")
sc.send(IPv6/IPv6HopByHopOptionsToRouting/IPv6RoutingOptionsToFragment/IPv6FragmentOffsetTCP/TCP/"TEST - IPv6 with Hop by Hop extension header and options and with Routing extension header and addresses and with Fragment extension header and offset + TCP")

# IPv6 with TCP and extension headers with options
sc.send(IPv6/AuthenticationPaylaodTCP/TCP/"TEST - IPv6 with Authentication extension header and payload + TCP")
sc.send(IPv6/IPv6RoutingOptionsTCP/TCP/"TEST - IPv6 with Routing extension header and addresses + TCP")
sc.send(IPv6/IPv6HopByHopOptionsTCP/TCP/"TEST - IPv6 with Hop by Hop extension header and options + TCP")
sc.send(IPv6/IPv6FragmentOffsetTCP/TCP/"TEST - IPv6 with Fragment extension header and offset + TCP")
sc.send(IPv6/IPv6DestinationOptionsTCP/TCP/"TEST - IPv6 with Destination extension header and options + TCP")

# IPv6 with UDP and extension headers with options
sc.send(IPv6/AuthenticationPaylaodUDP/UDP/"TEST - IPv6 with Authentication extension header and payload + UDP")
sc.send(IPv6/IPv6RoutingOptionsUDP/UDP/"TEST - IPv6 with Routing extension header and addresses + UDP")
sc.send(IPv6/IPv6HopByHopOptionsUDP/UDP/"TEST - IPv6 with Hop by Hop extension header and options + UDP")
sc.send(IPv6/IPv6FragmentOffsetUDP/UDP/"TEST - IPv6 with Fragment extension header and offset + UDP")
sc.send(IPv6/IPv6DestinationOptionsUDP/UDP/"TEST - IPv6 with Destination extension header and options + UDP")

# IPv6 with TCP and multiple extesion headers
sc.send(IPv6/IPv6HopByHopToRouting/IPv6RoutingTCP/TCP/"TEST - IPv6 with Hop by Hop extension header and with Routing extension header + TCP")
sc.send(IPv6/IPv6DestinationToFragment/IPv6FragmentTCP/TCP/"TEST - IPv6 with Destination extension header and with Fragment extension header + TCP")
sc.send(IPv6/IPv6HopByHopToDestination/IPv6DestinationTCP/TCP/"TEST - IPv6 with Hop by Hop extension header and with Destination extension header + TCP")
sc.send(IPv6/IPv6HopByHopToDestination/IPv6DestinationToFragment/IPv6FragmentTCP/TCP/"TEST - IPv6 with Hop by Hop extension header and with Destination extension header and with Fragment extension header + TCP")
sc.send(IPv6/IPv6HopByHopToDestination/IPv6DestinationToFragment/IPv6FragmentToDestination/IPv6DestinationTCP/TCP/"TEST - IPv6 with Hop by Hop extension header and with Destination extension header and with Fragment extension header and with Destination extension header + TCP")
sc.send(IPv6/IPv6HopByHopToFragment/IPv6FragmentTCP/TCP/"TEST - IPv6 with Hop by Hop extension header and with Fragment extension header + TCP")

# IPv6 with UDP and multiple extesion headers
sc.send(IPv6/IPv6HopByHopToRouting/IPv6RoutingUDP/UDP/"TEST - IPv6 with Hop by Hop extension header and with Routing extension header + UDP")
sc.send(IPv6/IPv6DestinationToFragment/IPv6FragmentUDP/UDP/"TEST - IPv6 with Destination extension header and with Fragment extension header + UDP")
sc.send(IPv6/IPv6HopByHopToDestination/IPv6DestinationUDP/UDP/"TEST - IPv6 with Hop by Hop extension header and with Destination extension header + UDP")
sc.send(IPv6/IPv6HopByHopToDestination/IPv6DestinationToFragment/IPv6FragmentUDP/UDP/"TEST - IPv6 with Hop by Hop extension header and with Destination extension header and with Fragment extension header + UDP")
sc.send(IPv6/IPv6HopByHopToDestination/IPv6DestinationToFragment/IPv6FragmentToDestination/IPv6DestinationUDP/UDP/"TEST - IPv6 with Hop by Hop extension header and with Destination extension header and with Fragment extension header and with Destination extension header + UDP")
sc.send(IPv6/IPv6HopByHopToRouting/IPv6FragmentUDP/UDP/"TEST - IPv6 with Hop by Hop extension header and with Fragment extension header + UDP")

# IPv6 with TCP and extension headers
sc.send(IPv6/TCP)
sc.send(IPv6/TCP/"TEST - IPv6 + TCP")
sc.send(IPv6/IPv6HopByHopTCP/TCP/"TEST - IPv6 with Hop By Hop extension header + TCP")
sc.send(IPv6/IPv6RoutingTCP/TCP/"TEST - IPv6 with Routing extension header + TCP")
sc.send(IPv6/IPv6FragmentTCP/TCP/"TEST - IPv6 with Fragment extension header + TCP")
sc.send(IPv6/IPv6DestinationTCP/TCP/"TEST - IPv6 with Destination Options extension header + TCP")
sc.send(IPv6/AuthenticationTCP/TCP/"TEST - IPv6 with Authentication extension header + TCP")
sc.send(IPv6/ESP/TCP/"TEST - IPv6 with EPS extension header + TCP")

# IPv6 with UDP and extension headers
sc.send(IPv6/UDP)
sc.send(IPv6/UDP/"TEST - IPv6 + UDP")
sc.send(IPv6/IPv6HopByHopUDP/UDP/"TEST - IPv6 with Hop By Hop extension header + UDP")
sc.send(IPv6/IPv6RoutingUDP/UDP/"TEST - IPv6 with Routing extension header + UDP")
sc.send(IPv6/IPv6FragmentUDP/UDP/"TEST - IPv6 with Fragment extension header + UDP")
sc.send(IPv6/IPv6DestinationUDP/UDP/"TEST - IPv6 with Destination Options extension header + UDP")
sc.send(IPv6/AuthenticationUDP/UDP/"TEST - IPv6 with Authentication extension header + UDP")

# IPv6 with ICMP and extension headers
sc.send(IPv6/IPv6HopByHopICMP/ICMP)
sc.send(IPv6/IPv6HopByHopICMP/ICMP/"TEST - IPv6 with Hop By Hop extension header + ICMP")
sc.send(IPv6/IPv6RoutingICMP/ICMP/"TEST - IPv6 with Routing extension header + ICMP")
sc.send(IPv6/IPv6FragmentICMP/ICMP)
sc.send(IPv6/IPv6FragmentICMP/ICMP/"TEST - IPv6 with Fragment extension header + ICMP")
sc.send(IPv6/IPv6DestinationICMP/ICMP/"TEST - IPv6 with Destination Options extension header + ICMP")
sc.send(IPv6/AuthenticationICMP/ICMP/"TEST - IPv6 with Authentication extension header + ICMP")

# IPv6 with ICMPv6 protocols and with extension headers
sc.send(IPv6/ICMPv6EchoRequest/"TEST - IPv6 + ICMPv6EchoRequest")
sc.send(IPv6/ICMPv6DestUnreach/"TEST - IPv6 + ICMPv6DestUnreach")
sc.send(IPv6/ICMPv6MLQuery/"TEST - IPv6 + ICMPv6MLQuery")
sc.send(IPv6/IPv6HopByHopICMP/ICMPv6EchoRequest/"TEST - IPv6 with Hop By Hop extension header + ICMPv6EchoRequest")
sc.send(IPv6/IPv6RoutingICMP/ICMPv6EchoRequest/"TEST - IPv6 with Routing extension header + ICMPv6EchoRequest")
sc.send(IPv6/IPv6FragmentICMP/ICMPv6DestUnreach/"TEST - IPv6 with Fragment extension header + ICMPv6DestUnreach")
sc.send(IPv6/IPv6DestinationICMP/ICMPv6DestUnreach/"TEST - IPv6 with Destination Options extension header + ICMPv6DestUnreach")
sc.send(IPv6/AuthenticationICMP/ICMPv6DestUnreach/"TEST - IPv6 with Authentication extension header + ICMPv6DestUnreach")
