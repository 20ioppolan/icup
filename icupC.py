from scapy.all import *
from scapy.all import IP,ICMP

def handle(pkt):
    print(pkt)

sniff(filter="icmp", prn=handle)
