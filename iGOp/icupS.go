package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/google/gopacket"
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

func generate_packet() {
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buff := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buff, opts, ethLayer, ipLayer, icmpLayer)
}

func main() {
	print_title()
	// print_help()
	// addclient("127.0.0.1")
	// addclient("127.0.0.2")
	// showclients()

	for {
		consoleReader := bufio.NewReader(os.Stdin)
		fmt.Print(">> ")

		input, _ := consoleReader.ReadString('\n')

		input = strings.ToLower(input)

		if strings.HasPrefix(input, "add") {
			tokens := strings.Split(input, " ")
			addclient(tokens[1])
		} else if strings.HasPrefix(input, "rm") {
			tokens := strings.Split(input, " ")
			clientid := tokens[1]
			atoiclient, _ := strconv.Atoi(strings.TrimRight(clientid, "\r\n"))
			removeclient(atoiclient)
		} else if strings.HasPrefix(input, "removeallclients") {
			removeallclients()
		} else if strings.HasPrefix(input, "ls") {
			showclients()
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
