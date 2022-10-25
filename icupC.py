from scapy.all import *
from scapy.all import IP,ICMP

def handle(message):
    print(b"message")

sniff(filter="icmp", prn=lambda x:handle(x))
