from scapy.all import *
from scapy.all import IP,ICMP

def handle(pkt):
    pkt.show()

sniff(filter="icmp", prn=handle)
