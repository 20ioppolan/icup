from scapy.all import *
from scapy.all import IP,ICMP

sniff(prn=lambda x:x.sprintf("%Raw.laod%"))

# for packet in pkts:
#      if  str(packet.getlayer(ICMP).type) == "8": 
#         print(packet[IP].src)