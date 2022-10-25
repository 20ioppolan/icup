from scapy.all import * 
from scapy.all import ICMP,IP

DEBUG = True

def print_help():
    print("\taddclient <IP_ADDRESS>   Adds new client by IP")
    print("\tshowclients              Show all added clients")
    print("\tremoveclient <ID>        Removes a client by ID")
    print("\tremoveallclients         Removes all clients")
    print("\tsend <ID> <message>      Send message to client at ID")
    print("\tsendtoall <message>      Sends <message> to all clients")
    print("\tkill                     Stops server")
    print("\thelp                     Prints this")

def main():
    clients = dict()
    id = 0
    while(True):
        command = input(">> ")
        arguments = command.split(" ", 1)
        if arguments[0] == "":
            continue

        elif arguments[0] == "addclient":
            clients[id] = arguments[1] 
            if DEBUG: print(f"[DEBUG] Client {id} added at {clients.get(id)}") 
            id += 1

        elif arguments[0] == "showclients":
            for client in clients:
                print(f"Client {client} at {clients.get(client)}")

        elif arguments[0] == "removeclient":
            if len(arguments)<2: print("Specify client by ID"); continue
            if DEBUG: print(f"[DEBUG] Client {arguments[1]} removed from {clients.get(int(arguments[1]))}") 
            clients.pop(int(arguments[1]))
        
        elif arguments[0] == "removeallclients":
            clients.clear()
            if DEBUG: print(f"[DEBUG] All clients removed")

        elif arguments[0] == "send":
            clientcommand = arguments[1] 
            clienttokens = clientcommand.split(" ", 1)
            if clients.get(int(clienttokens[0])) != None:
                evil = IP(dst=clients.get(int(clienttokens[0])))/ICMP(type=8)/(clienttokens[1])
                send(evil)
                if DEBUG: print(f"[DEBUG] \"{clienttokens[1]}\" sent to {clienttokens[0]} at {clients.get(int(clienttokens[0]))}")
            else:
                print(f"[ERROR] No client at ID {clienttokens[0]}")

        elif arguments[0] == "sendtoall":
            for client in clients:
                evil = IP(dst=clients.get(client))/ICMP(type=8)/(arguments[1])
                if DEBUG: print(f"[DEBUG] \"{arguments[1]}\" sent to {client} at {clients.get(client)}")
                send(evil)

        elif arguments[0] == "kill":
            break

        elif arguments[0] == "help":
            print_help()

        else:
            print("Invalid option, use \"help\" for available commands")


if __name__ == "__main__":
    main()