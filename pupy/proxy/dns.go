package main

import (
	"log"

	"net"
	"strings"
	"time"

	dns "github.com/miekg/dns"
)

func (d *Daemon) serveDNS(conn net.Conn, domain string) error {
	d.DNSListener = NewDNSListener(conn, domain)
	log.Println("SERVE DNSCNC CONNECTION")
	err := d.DNSListener.Serve()
	log.Println("DNSCNC CONNECTION FAILED: ", err)
	return err
}

func (p *DNSListener) listenAndServeTCP(cherr chan error) {
	err := p.TCPServer.ListenAndServe()
	if err != nil {
		log.Printf("Couldn't start TCP DNS listener: %s\n", err.Error())
	}

	cherr <- err
	log.Println("[1.] DNS TCP CLOSED")
}

func (p *DNSListener) listenAndServeUDP(cherr chan error) {
	err := p.UDPServer.ListenAndServe()
	if err != nil {
		log.Printf("Couldn't start TCP DNS listener: %s\n", err.Error())
	}

	cherr <- err
	log.Println("[2.] DNS UDP CLOSED")
}

func (p *DNSListener) messageReader(cherr chan error, chmsg chan []string) {
	for {
		var response []string

		err := RecvMessage(p.Conn, &response)
		if err != nil || response == nil {
			cherr <- err
			break
		} else {
			chmsg <- response
		}
	}

	log.Println("[3.] REMOTE READER CLOSED")
}

func (p *DNSListener) messageProcessor(
	recvStrings chan []string, interrupt <-chan bool, closeNotify chan<- bool, decoderr chan<- error) {

	ignore := false

	for {
		var (
			err error
			r   *DNSRequest
		)

		r = nil
		interrupted := false

		select {
		case r = <-p.DNSRequests:
		case _ = <-interrupt:
			interrupted = true
		}

		if r == nil || interrupted {
			if !ignore {
				closeNotify <- true
			}

			ignore = true
		}

		if ignore {
			if r != nil {
				r.IPs <- []string{}
				continue
			} else {
				break
			}
		}

		err = SendMessage(p.Conn, r.Name)
		if err != nil {
			r.IPs <- []string{}
			decoderr <- err
			ignore = true
			continue
		}

		select {
		case ips := <-recvStrings:
			r.IPs <- ips
		case _ = <-interrupt:
			r.IPs <- []string{}
			ignore = true
		}
	}

	log.Println("DNS READ/WRITE CLOSED")
}

func (p *DNSListener) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true

	processed := true

	now := time.Now()

	for k, v := range p.DNSCache {
		if v.LastActivity.Add(1 * time.Minute).Before(now) {
			log.Println("Delete cache: ", k)
			delete(p.DNSCache, k)
		}
	}

	if len(r.Question) > 0 {
		for _, q := range r.Question {
			log.Println("Request Name: ", q.Name)

			if _, ok := p.DNSCache[q.Name]; !ok {
				log.Println(q.Name, " not in cache")

				question := q.Name[:]
				if q.Name[len(q.Name)-1] == '.' {
					question = q.Name[:len(q.Name)-1]
				}

				if strings.HasSuffix(question, p.Domain) {
					question = question[:len(question)-len(p.Domain)-1]

					result := make(chan []string)
					p.DNSRequests <- &DNSRequest{
						Name: question,
						IPs:  result,
					}

					responses := <-result
					log.Println("Result: ", responses)
					defer close(result)

					if len(responses) > 0 {
						dnsResponses := make([]dns.RR, len(responses))

						for i, response := range responses {
							a := new(dns.A)
							a.Hdr = dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    10,
							}
							a.A = net.ParseIP(response).To4()
							dnsResponses[i] = a
						}

						p.DNSCache[q.Name] = &DNSCacheRecord{
							ResponseRecords: dnsResponses,
						}
					} else {
						processed = false
					}
				} else {
					processed = false
				}
			}

			if processed {
				for _, rr := range p.DNSCache[q.Name].ResponseRecords {
					m.Answer = append(m.Answer, rr)
				}

				p.DNSCache[q.Name].LastActivity = now
			}
		}
	}

	w.WriteMsg(m)
}

func NewDNSListener(conn net.Conn, domain string) *DNSListener {
	listener := &DNSListener{
		Conn:   conn,
		Domain: domain,

		DNSCache: make(map[string]*DNSCacheRecord),
		UDPServer: &dns.Server{
			Addr:    "0.0.0.0:5454",
			Net:     "udp",
			UDPSize: 1400,
		},
		TCPServer: &dns.Server{
			Addr: "0.0.0.0:5454",
			Net:  "tcp",
		},
		DNSRequests: make(chan *DNSRequest),

		active: true,
	}

	listener.UDPServer.Handler = listener
	listener.TCPServer.Handler = listener

	return listener
}

func (p *DNSListener) Serve() error {
	/* Add error handling */

	tcperr := make(chan error)
	udperr := make(chan error)
	decoderr := make(chan error)
	recvStrings := make(chan []string)
	recvErrors := make(chan error)
	closeNotify := make(chan bool)
	interruptNotify := make(chan bool)

	defer close(tcperr)
	defer close(udperr)
	defer close(decoderr)
	defer close(recvStrings)
	defer close(recvErrors)
	defer close(closeNotify)
	defer close(interruptNotify)

	go p.listenAndServeTCP(tcperr)
	go p.listenAndServeUDP(udperr)
	go p.messageReader(recvErrors, recvStrings)
	go p.messageProcessor(recvStrings, interruptNotify, closeNotify, decoderr)

	var err error

	tcpClosed := false
	udpClosed := false
	decoderClosed := false
	msgsClosed := false
	shutdown := false

	for !(tcpClosed && udpClosed && decoderClosed && msgsClosed) {
		var err2 error
		select {
		case err2 = <-tcperr:
			tcpClosed = true

		case err2 = <-udperr:
			udpClosed = true

		case err2 = <-decoderr:
			decoderClosed = true

		case err2 = <-recvErrors:
			msgsClosed = true
			interruptNotify <- true

		case <-closeNotify:
			shutdown = true
			decoderClosed = true
		}

		p.Shutdown()

		if err == nil {
			err = err2
		}

		log.Println("CLOSED: ", tcpClosed, udpClosed, decoderClosed, msgsClosed, shutdown)
	}

	return err
}

func (p *DNSListener) Shutdown() {
	if p.active {
		p.UDPServer.Shutdown()
		p.TCPServer.Shutdown()
		close(p.DNSRequests)
		p.Conn.Close()
		p.active = false
	}
}
