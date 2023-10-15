package main

import (
    "log"
    "net"
    "time"
    "golang.org/x/net/context"
    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
)

// Create a custom FTP packet with the specified payload
func MakeFTPPacket(payload string) {
    // Replace these values with your server's IP and port
    serverIP := "127.0.0.1"
    serverPort := 21

    // Create an FTP payload with the specified data
    ftpPayload := "USER anonymous\r\nPASS yourpassword\r\n" + payload + "\r\n"

    // Resolve the FTP server address
    serverAddr, err := net.ResolveUDPAddr("udp4", serverIP)
    if err != nil {
        log.Fatal(err)
        return
    }

    // Create a connection to the FTP server
    conn, err := net.DialUDP("udp4", nil, serverAddr)
    if err != nil {
        log.Fatal(err)
        return
    }
    defer conn.Close()

    // Set a timeout for the connection
    conn.SetDeadline(time.Now().Add(5 * time.Second))

    // Send the FTP payload to the server
    _, err = conn.Write([]byte(ftpPayload))
    if err != nil {
        log.Fatal(err)
    }
}

func main() {
    payload := "Custom FTP Command"
    MakeFTPPacket(payload)
}
