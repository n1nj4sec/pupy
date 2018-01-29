package main

import (
	"log"
	"net"

	"crypto/rand"
	"crypto/sha256"
)

func NewDaemon(addr string) *Daemon {
	return &Daemon{
		Addr:      addr,
		Listeners: make(map[int]*Listener),
	}
}

func (d *Daemon) ListenAndServe() error {
	listener, err := net.Listen("tcp", d.Addr)
	if err != nil {
		log.Println("Listen error: ", err)
		return err
	}

	for {
		conn, err := listener.Accept()
		log.Println("HANDLE INCOMING CONNECTION")
		if err != nil {
			log.Println("Accept error: ", err)
			return err
		}

		go d.handle(conn)
	}

	return nil
}

func (d *Daemon) handle(conn net.Conn) {
	defer conn.Close()

	Nonce := make([]byte, sha256.BlockSize)
	_, err := rand.Read(Nonce)
	if err != nil {
		log.Println("Nonce generation error: ", err)
		return
	}

	err = SendMessage(conn, Nonce)
	if err != nil {
		log.Println("Couldn't send nonce: ", err)
		return
	}

	brh := &BindRequestHeader{}

	err = RecvMessage(conn, brh)
	if err != nil {
		log.Println("Couldn't read bind request: ", err)
		return
	}

	log.Println(brh)

	/* Check PSK */

	log.Println("PROTOCOL CODE: ", brh.Protocol)

	switch brh.Protocol {
	case DNS:
		/* Check DNS Already served */

		d.DNSCheck.Lock()
		if d.DNSListener != nil {
			d.DNSListener.Shutdown()
		}
		d.DNSCheck.Unlock()

		d.DNSLock.Lock()
		d.serveDNS(conn, brh.BindInfo)
		d.DNSCheck.Lock()
		d.DNSListener = nil
		d.DNSCheck.Unlock()
		d.DNSLock.Unlock()

	case TCP:
		log.Printf("Start TCP handler with port: %s", brh.BindInfo)
		d.serveStream(conn, brh.BindInfo, d.listenAcceptTCP)
	case KCP:
		log.Printf("Start KCP handler with port: %s", brh.BindInfo)
		d.serveStream(conn, brh.BindInfo, d.listenAcceptKCP)
	default:
		log.Println("Unknown protocol")
	}
}
