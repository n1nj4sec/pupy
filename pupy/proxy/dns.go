package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	dns "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

func (d *Daemon) serveDNS(conn net.Conn, domain string) error {
	d.DNSCheck.Lock()
	d.DNSListener = NewDNSListener(conn, domain)
	d.DNSCheck.Unlock()

	log.Debug("DNS: Enabled: ", domain)
	err := d.DNSListener.Serve()
	log.Debug("DNS: Disabled: ", domain, err)

	d.DNSCheck.Lock()
	d.DNSListener = nil
	d.DNSCheck.Unlock()
	return err
}

func (p *DNSListener) listenAndServeTCP(cherr chan error) {
	err := p.TCPServer.ListenAndServe()
	if err != nil {
		log.Error("Couldn't start TCP DNS listener:", err)
	}

	cherr <- err
	log.Debug("[1.] DNS TCP CLOSED")
}

func (p *DNSListener) listenAndServeUDP(cherr chan error) {
	err := p.UDPServer.ListenAndServe()
	if err != nil {
		log.Error("Couldn't start TCP DNS listener:", err)
	}

	cherr <- err
	log.Debug("[2.] DNS UDP CLOSED")
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

	log.Debug("[3.] REMOTE READER CLOSED")
}

func (p *DNSListener) messageProcessor(
	recvStrings chan []string, interrupt <-chan bool, closeNotify chan<- bool, decoderr chan<- error) {
	ignore := false
	notifySent := false

	for {
		var (
			err error
			r   *DNSRequest
		)

		r = nil
		interrupted := false

		log.Debug("DNS. Wait for interrupt or for close request")

		select {
		case r = <-p.DNSRequests:
		case _ = <-interrupt:
			interrupted = true
		}

		log.Debug("DNS. Wait done", r, ignore)

		if r == nil || interrupted {
			if !notifySent {
				log.Debug("Send close notify")
				closeNotify <- true
				notifySent = true
			}

			log.Debug("Ignore 1")
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
			log.Debug("Ignore 2")
			ignore = true
			continue
		}

		log.Debug("DNS. Wait for response or for interrupt")
		select {
		case ips := <-recvStrings:
			r.IPs <- ips
		case _ = <-interrupt:
			r.IPs <- []string{}
			ignore = true
		}
		log.Debug("DNS. Wait for response or for interrupt completed")
	}

	for {
		select {
		case r := <-p.DNSRequests:
			if r != nil {
				r.IPs <- []string{}
			}
		default:
			break
		}
	}

	log.Debug("[4.] Message processor closed")
}

func (p *DNSListener) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true

	processed := true

	now := time.Now()

	log.Debug("START PROCESSING REQUEST")
	defer log.Debug("END PROCESSING REQUEST")

	p.processedRequests.Add(1)
	defer p.processedRequests.Done()

	p.cacheLock.Lock()
	for k, v := range p.DNSCache {
		if v.LastActivity.Add(1 * time.Minute).Before(now) {
			log.Debug("Delete cache: ", k)
			delete(p.DNSCache, k)
		}
	}
	p.cacheLock.Unlock()

	if len(r.Question) > 0 {
		for _, q := range r.Question {

			log.Debug("DNS: Request: ", q.Name)
			p.cacheLock.Lock()
			record, ok := p.DNSCache[q.Name]
			p.cacheLock.Unlock()

			if !ok {
				log.Info("DNS: Request: ", q.Name, " not in cache")

				question := q.Name[:]
				if q.Name[len(q.Name)-1] == '.' {
					question = q.Name[:len(q.Name)-1]
				}

				responses := []string{}

				if strings.HasSuffix(question, p.Domain) {
					if p.active {
						question = question[:len(question)-len(p.Domain)-1]
						result := make(chan []string)

						p.DNSRequests <- &DNSRequest{
							Name: question,
							IPs:  result,
						}
						log.Debug("DNS: Send request: ", q.Name)
						responses = <-result
						log.Info("DNS: Response: ", q.Name, ": ", responses)
						close(result)
					}

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

						record = &DNSCacheRecord{
							ResponseRecords: dnsResponses,
						}

						p.cacheLock.Lock()
						p.DNSCache[q.Name] = record
						p.cacheLock.Unlock()
					} else {
						processed = false
					}
				} else {
					processed = false
				}
			}

			if processed {
				for _, rr := range record.ResponseRecords {
					m.Answer = append(m.Answer, rr)
				}

				record.LastActivity = now
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
			Addr:    fmt.Sprintf("%s:%d", ExternalBindHost, DnsBindPort),
			Net:     "udp",
			UDPSize: int(UDPSize),
		},
		TCPServer: &dns.Server{
			Addr: fmt.Sprintf("%s:%d", ExternalBindHost, DnsBindPort),
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
			log.Println("Recv tcpClosed")
			tcpClosed = true

		case err2 = <-udperr:
			log.Println("Recv udpClosed")
			udpClosed = true

		case err2 = <-decoderr:
			log.Println("Recv decoderClosed")
			decoderClosed = true

		case err2 = <-recvErrors:
			log.Println("Recv msgsClosed")
			msgsClosed = true
			close(interruptNotify)

		case <-closeNotify:
			log.Println("Recv decoderClosed")
			shutdown = true
			decoderClosed = true
		}

		log.Debug("Call closed")
		p.Shutdown()
		log.Debug("Call closed complete")

		if err == nil {
			err = err2
		}

		log.Debug("CLOSED: ", tcpClosed, udpClosed, decoderClosed, msgsClosed, shutdown)
	}

	log.Debug("Wait process group complete")
	p.processedRequests.Wait()
	log.Debug("Wait process group complete - done")
	close(p.DNSRequests)
	p.DNSRequests = nil

	return err
}

func (p *DNSListener) Shutdown() {
	p.activeLock.Lock()
	if p.active {
		p.active = false
		p.UDPServer.Shutdown()
		p.TCPServer.Shutdown()
		p.Conn.Close()
		log.Debug("CLOSING DNS REQUESTS")
		log.Debug("DNS REQUESTS CLOSED")
	}
	p.activeLock.Unlock()
}
