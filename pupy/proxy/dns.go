package main

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"errors"

	dns "github.com/miekg/dns"
	rc "github.com/paulbellamy/ratecounter"
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
			log.Error("DNS: RecvMessage failed: ", err)
			cherr <- err
			break
		} else {
			r := atomic.AddInt32(&p.pendingRequests, -1)
			if r == 0 {
				p.Conn.SetDeadline(time.Time{})
			}
			chmsg <- response

		}
	}

	close(chmsg)
	log.Debug("[3.] REMOTE READER CLOSED")
}

func (p *DNSListener) responseProcessor(queue chan chan []string, recvStrings chan []string) {
	for {
		response := <-recvStrings

		if response == nil {
			break
		}

		rchan := <-queue
		if rchan == nil {
			break
		}

		rchan <- response
	}

waitLoop:
	for {
		select {
		case ignore := <-queue:
			if ignore == nil {
				break waitLoop
			}

			ignore <- []string{}
		default:
			break waitLoop
		}
	}

	log.Debug("[5.] RESPONSE PROCESSOR CLOSED")
}

func (p *DNSListener) sendEmptyMessage() {
	SendMessage(p.Conn, "")
}

func (p *DNSListener) queryProcessor(
	queue chan chan []string,
	interrupt <-chan bool, closeNotify chan<- bool, decoderr chan<- error) {

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

		log.Debug("DNS. Wait done: ", r, ignore)

		if r == nil || interrupted {
			if interrupted {
				log.Error("DNS: Interrupt request received", notifySent)
			}

			if !notifySent {
				log.Debug("Send close notify")
				closeNotify <- true
				notifySent = true
				close(closeNotify)
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

		p.Conn.SetDeadline(time.Now().Add(20 * time.Second))

		err = SendMessage(p.Conn, r.Name)
		if err != nil {
			log.Error("DNS: Send message failed: ", err)
			r.IPs <- []string{}
			decoderr <- err
			ignore = true
			continue
		} else {
			if atomic.AddInt32(&p.pendingRequests, 1) > 512 {
				r.IPs <- []string{}
				decoderr <- errors.New("Too many pending requests")
				ignore = true
				continue
			} else {
				queue <- r.IPs
			}
		}
	}

waitLoop:
	for {
		select {
		case r := <-p.DNSRequests:
			if r != nil {
				r.IPs <- []string{}
			}
		default:
			break waitLoop
		}
	}

	log.Debug("[4.] Message processor closed")
}

func warnSlow(message string, now time.Time, max time.Duration) {
	current := time.Now()
	barrier := now.Add(max)
	diff := current.Sub(now).Seconds()

	if barrier.Before(current) {
		log.Warning(fmt.Sprintf("%s: %.2fs", message, diff))
	}
}

func (p *DNSListener) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = false

	processed := true

	now := time.Now()
	result := make(chan []string)

	p.dnsRequestsCounter.Incr(1)
	defer p.dnsProcessedRequestsCounter.Incr(1)

	p.processedRequests.Add(1)
	defer p.processedRequests.Done()
	defer close(result)

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
			question := q.Name[:]
			if q.Name[len(q.Name)-1] == '.' {
				question = q.Name[:len(q.Name)-1]
			}

			payloadLen := len(question) - len(p.Domain) - 1

			log.Debug("DNS: Request: ", q.Name)
			p.cacheLock.Lock()
			record, ok := p.DNSCache[q.Name]
			p.cacheLock.Unlock()

			if !ok {
				log.Info("DNS: Request: ", q.Name, " not in cache")

				responses := []string{}

				if strings.HasSuffix(question, p.Domain) && payloadLen > 0 {
					if p.active {
						p.dnsRemoteRequestsCounter.Incr(1)

						if payloadLen <= len(question) {
							question = question[:payloadLen]

							now2 := time.Now()

							p.DNSRequests <- &DNSRequest{
								Name: question,
								IPs:  result,
							}

							log.Debug("DNS: Send request: ", q.Name)
							responses = <-result
							log.Info("DNS: Response: ", q.Name, ": ", responses)

							warnSlow(fmt.Sprintf(
								"DNS: Slow RR communication: (Rates: Remote=%dps Total=%dps Processed=%dps)",
								p.dnsRemoteRequestsCounter.Rate()/10,
								p.dnsRequestsCounter.Rate()/10,
								p.dnsProcessedRequestsCounter.Rate()/10,
							), now2, 1*time.Second)
						}
					}

					if len(responses) > 0 {
						dnsResponses := make([]dns.RR, len(responses))

						for i, response := range responses {
							a := new(dns.A)
							a.Hdr = dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    60,
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

		dnsRequestsCounter:          rc.NewRateCounter(10 * time.Second),
		dnsRemoteRequestsCounter:    rc.NewRateCounter(10 * time.Second),
		dnsProcessedRequestsCounter: rc.NewRateCounter(10 * time.Second),

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
	responsesQueue := make(chan chan []string, 512)

	defer close(tcperr)
	defer close(udperr)
	defer close(decoderr)
	defer close(recvErrors)
	defer close(responsesQueue)

	go p.listenAndServeTCP(tcperr)
	go p.listenAndServeUDP(udperr)
	go p.messageReader(recvErrors, recvStrings)
	go p.queryProcessor(responsesQueue, interruptNotify, closeNotify, decoderr)
	go p.responseProcessor(responsesQueue, recvStrings)

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
