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

	switch brh.Protocol {
	case DNS:
		/* Check DNS Already served */

		log.Info("Request: DNS Handler for domain:", brh.BindInfo, " - start")
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
		log.Info("Request: DNS Handler for domain:", brh.BindInfo, " - complete")

	case INFO:
		ip := GetOutboundIP()
		if CheckExternalBindHostIP() {
			ip = ExternalBindHost
		}

		log.Info("Request: External IP:", ip)

		SendMessage(conn, &IPInfo{
			IP: ip,
		})

	case TCP:
		log.Info("Request: TCP handler with port:", brh.BindInfo, " - start")
		d.serveStream(-1, conn, brh.BindInfo, d.listenAcceptTCP)
		log.Info("Request: TCP handler with port:", brh.BindInfo, " - complete")

	case KCP:
		log.Info("Request: KCP handler with port:", brh.BindInfo, " - start")
		d.serveStream(1376, conn, brh.BindInfo, d.listenAcceptKCP)
		log.Info("Request: KCP handler with port:", brh.BindInfo, " - complete")

	case TLS:
		log.Info("Request: SSL handler with port:", brh.BindInfo, " - start")
		d.serveStream(-1, conn, brh.BindInfo, d.listenAcceptTLS)
		log.Info("Request: SSL handler with port:", brh.BindInfo, " - complete")

	default:
		log.Error("Unknown protocol", brh.Protocol)
	}
}
