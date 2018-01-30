package main

import (
	"crypto/tls"
	"net"

	log "github.com/sirupsen/logrus"
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
		log.Error("Listen error: ", err)
		return err
	}

	for {
		conn, err := listener.Accept()
		log.Debug("HANDLE INCOMING CONNECTION")
		if err != nil {
			log.Error("Accept error: ", err)
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
		log.Error("Couldn't read bind request: ", err)
		return
	}

	log.Debug(brh)

	/* Check PSK */

	log.Debug("PROTOCOL CODE: ", brh.Protocol)

	client := conn.RemoteAddr().String()

	switch brh.Protocol {
	case DNS:
		/* Check DNS Already served */

		log.Warning("Request: DNS Handler for domain:", brh.BindInfo, " client: ", client, " - start")
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
		log.Warning("Request: DNS Handler for domain:", brh.BindInfo, " client: ", client, " - complete")

	case INFO:
		ip := GetOutboundIP()
		if CheckExternalBindHostIP() {
			ip = ExternalBindHost
		}

		log.Warning("Request: External IP:", ip)

		SendMessage(conn, &IPInfo{
			IP: ip,
		})

	case TCP:
		log.Warning("Request: TCP handler with port:", brh.BindInfo, " client: ", client, " - start")
		d.serveStream(-1, conn, brh.BindInfo, d.listenAcceptTCP)
		log.Warning("Request: TCP handler with port:", brh.BindInfo, " client: ", client, " - complete")

	case KCP:
		log.Warning("Request: KCP handler with port:", brh.BindInfo, " client: ", client, " - start")
		d.serveStream(int(UDPSize-24), conn, brh.BindInfo, d.listenAcceptKCP)
		log.Warning("Request: KCP handler with port:", brh.BindInfo, " client: ", client, " - complete")

	case TLS:
		log.Warning("Request: SSL handler with port:", brh.BindInfo, " client: ", client, " - start")
		d.serveStream(-1, conn, brh.BindInfo, d.listenAcceptTLS)
		log.Warning("Request: SSL handler with port:", brh.BindInfo, " client: ", client, " - complete")

	default:
		log.Error("Unknown protocol", brh.Protocol)
	}
}
