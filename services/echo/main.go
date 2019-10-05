package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"github.com/LiamHaworth/go-tproxy"
)

var (
	EchoBindHost = "0.0.0.0"
	EchoBindPort = 31337
	EchoMagic    = "\xDE\xAD\xBE\xEF"
)

func isHttpEchoRequest(body []byte) bool {
	buf := bufio.NewReader(bytes.NewReader(body))
	req, err := http.ReadRequest(buf)
	if err != nil {
		return false
	}

	for k, v := range req.URL.Query() {
		if strings.ToLower(k) == "echo" {
			for _, value := range v {
				if value == EchoMagic {
					return true
				}
			}
		}
	}

	return false
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 32768)

	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	switch {
	case isHttpEchoRequest(buffer):
		log.Println(
			"TCP/HTTP: "+conn.RemoteAddr().String(), "->",
			conn.LocalAddr().String(), " b: ", n,
		)
		conn.Write(
			[]byte(fmt.Sprintf(
				"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream"+
					"\r\nContent-Length: %d\r\n\r\n", n,
			)),
		)
	case bytes.Equal(buffer[:4], []byte(EchoMagic)):
		log.Println(
			"TCP/RAW: "+conn.RemoteAddr().String(), "->",
			conn.LocalAddr().String(), " b: ", n,
		)
	default:
		return
	}

	conn.Write(buffer[:n])
}

func tcpEchoServer(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				log.Printf("Temporary error while accepting connection: %s", netErr)
			}

			log.Fatalf("Unrecoverable error while accepting connection: %s", err)
			return
		}

		go handleConn(conn)
	}
}

func udpEchoServer(listener *net.UDPConn) {
	buffer := make([]byte, 1500)

	for {
		n, srcAddr, dstAddr, err := tproxy.ReadFromUDP(listener, buffer)
		if err != nil {
			log.Fatalln("UDP reader failed: ", err)
		}

		if srcAddr.IP.Equal(dstAddr.IP) || n < 4 {
			continue
		}

		if !bytes.Equal(buffer[:4], []byte(EchoMagic)) {
			continue
		}

		log.Println(
			"UDP: "+srcAddr.String(), "->",
			dstAddr.String(), " b: ", n,
		)

		remoteConn, err := tproxy.DialUDP("udp", dstAddr, srcAddr)
		if err != nil {
			log.Println(err)
			continue
		}

		_, err = remoteConn.Write(buffer[:n])
		if err != nil {
			log.Println(err)
			continue
		}
	}
}

func main() {
	log.Print("Echo server starting")

	log.Printf("Binding TCP TProxy listener to %s:%d", EchoBindHost, EchoBindPort)
	tcpListener, err := tproxy.ListenTCP(
		"tcp", &net.TCPAddr{
			IP:   net.ParseIP(EchoBindHost),
			Port: EchoBindPort,
		})

	if err != nil {
		log.Fatalf("Encountered error while binding listener: %s", err)
		return
	}

	udpListener, err := tproxy.ListenUDP(
		"udp", &net.UDPAddr{
			IP:   net.ParseIP(EchoBindHost),
			Port: EchoBindPort,
		})

	if err != nil {
		log.Fatalf("Encountered error while binding listener: %s", err)
		return
	}

	go tcpEchoServer(tcpListener)
	go udpEchoServer(udpListener)

	interruptListener := make(chan os.Signal)
	signal.Notify(interruptListener, os.Interrupt)
	<-interruptListener

	log.Println("Interrupted")
}
