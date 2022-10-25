from scapy.all import *
from scapy.all import IP,ICMP

def handle(pkt):
    print(pkt.summary())

sniff(filter="icmp", prn=handle)
