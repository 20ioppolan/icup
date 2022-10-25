from scapy.all import *
from scapy.all import IP,ICMP

def handle(pkt):
    print(raw(pkt))

sniff(filter="icmp", prn=handle)
