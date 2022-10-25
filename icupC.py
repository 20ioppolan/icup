from scapy.all import *
from scapy.all import IP,ICMP

def handle(message):
    print(message.decode())

sniff(filter="icmp", prn=lambda x:handle(x))
