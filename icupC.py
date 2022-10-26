from scapy.all import *
from scapy.all import IP,ICMP

def send_over_icmp(clientip, response):
    serverresponse = "###" + response
    evil = IP(dst=clientip)/ICMP(type=8)/(serverresponse)
    send(evil)

def handle(pkt):
    src = pkt[IP].dst
    payload = str(pkt.payload)
    parsed = re.split('!{3}', payload)
    if len(parsed) == 1:
        return
    else: 
        command = parsed[1][:-1]
        if command == "PING":
            send_over_icmp(src, "PONG")

sniff(filter="icmp[icmptype] == icmp-echoreply", prn=handle)
