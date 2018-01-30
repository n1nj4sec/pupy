package main

import (
	"log"
	"net"

	"crypto/tls"
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

		conn = tls.Server(conn, ListenerConfig)

		go d.handle(conn)
	}

	return nil
}

func (d *Daemon) handle(conn net.Conn) {
	defer conn.Close()

	brh := &BindRequestHeader{}

	err := RecvMessage(conn, brh)
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
		d.serveStream(65000, conn, brh.BindInfo, d.listenAcceptTCP)
	case KCP:
		log.Printf("Start KCP handler with port: %s", brh.BindInfo)
		d.serveStream(1376, conn, brh.BindInfo, d.listenAcceptKCP)
	default:
		log.Println("Unknown protocol")
	}
}
