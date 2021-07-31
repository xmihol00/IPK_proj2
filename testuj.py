
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

print("Filters")
i = 0
while i < 3:
    sc.send(IPv4/lr.TCP(dport=65004)/payload)
    i += 1

i = 0
while i < 3:
    sc.send(IPv4/lr.TCP(dport=65004)/payload)
    i += 1

i = 0
while i < 2:
    sc.send(IPv6/lr.TCP(dport=65004)/payload)
    i += 1

i = 0
while i < 2:
    sc.send(IPv6/lr.TCP(dport=65004)/payload)
    i += 1

sc.send(IPv4/ICMP/payload)
sc.send(IPv6/ICMPv6/payload)
sc.send(ARP/payload)
sc.send(IPv4/ICMP/payload)
sc.send(IPv6/ICMPv6/payload)
sc.send(ARP/payload)
