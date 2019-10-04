package main

import (
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/LiamHaworth/go-tproxy"
)

var (
	EchoBindHost = "0.0.0.0"
	EchoBindPort = 31337
)

func handleConn(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 32768)

	n, err := conn.Read(buffer)
	if err != nil {
		log.Println("TCP: "+conn.LocalAddr().String(), " err: ", err)
		return
	} else {
		log.Println("TCP: "+conn.LocalAddr().String(), " b: ", n)
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

		if srcAddr.IP.Equal(dstAddr.IP) {
			continue
		}

		log.Println("UDP: "+dstAddr.String(), " b: ", n)
		listener.WriteToUDP(buffer[:n], srcAddr)
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
