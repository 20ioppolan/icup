from scapy.all import *
from scapy.all import IP,ICMP

def handle(pkt):
    pkt.summary()

sniff(filter="icmp", prn=handle)
