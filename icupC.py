from scapy.all import *
from scapy.all import IP,ICMP

sniff(prn=lambda x:x.summary(), count=100)

# for packet in pkts:
#      if  str(packet.getlayer(ICMP).type) == "8": 
#         print(packet[IP].src)