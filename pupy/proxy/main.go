package main

import (
	"log"
	"net"
	"time"

	"crypto/rand"
	"crypto/sha256"

	"strconv"
	"sync"

	"encoding/binary"
	"encoding/hex"
	"strings"

	"fmt"
	"io"

	"os"
	"runtime/pprof"

	dns "github.com/miekg/dns"
	msgpack "github.com/vmihailenco/msgpack"
	kcp "github.com/xtaci/kcp-go"
)

type (
	Conn struct {
		in    chan []byte
		out   chan []byte
		close chan bool
	}

	Listener struct {
		Listener net.Listener
		refcnt   int
	}

	ListenerProtocol int
	BindRequestType  int
	Nonce            [sha256.BlockSize]byte

	BindRequestHeader struct {
		Nonce Nonce `msgpack:"nonce"`

		Protocol ListenerProtocol `msgpack:"prot"`
		BindInfo string           `msgpack:"bind"`
		Timeout  int              `msgpack:"timeout"`
	}

	DNSRequest struct {
		Name string
		IPs  chan []string
	}

	DNSCacheRecord struct {
		ResponseRecords []dns.RR
		LastActivity    time.Time
	}

	ConnectionAcceptHeader struct {
		LocalHost  string `msgpack:"lhost"`
		LocalPort  int    `msgpack:"lport"`
		RemoteHost string `msgpack:"rhost"`
		RemotePort int    `msgpack:"rport"`
		Error      string `msgpack:"error"`
	}

	DNSListener struct {
		Conn net.Conn

		Domain string

		DNSCache    map[string]*DNSCacheRecord
		UDPServer   *dns.Server
		TCPServer   *dns.Server
		DNSRequests chan *DNSRequest
	}

	Daemon struct {
		Addr string

		DNSLock     sync.Mutex
		DNSCheck    sync.Mutex
		DNSListener *DNSListener

		Listeners     map[int]*Listener
		ListenersLock sync.Mutex
	}
)

const (
	DNS ListenerProtocol = 0
	TCP ListenerProtocol = iota
	KCP ListenerProtocol = iota
)

var (
	PSK Nonce
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

func (d *Daemon) Accept(port int, createListener func() (net.Listener, error)) (net.Conn, error) {
	var (
		listener *Listener
		ok       bool
	)

	d.ListenersLock.Lock()
	if listener, ok = d.Listeners[port]; !ok {
		log.Printf("Create new listener [%d]\n", port)
		l, err := createListener()
		if err != nil {
			log.Printf("Create new listener [%d]: failed: %s\n", port, err.Error())
			d.ListenersLock.Unlock()
			return nil, err
		}

		listener = &Listener{
			Listener: l,
			refcnt:   0,
		}

		d.Listeners[port] = listener
		log.Printf("New listener [%d] created\n", port)
	}

	listener.refcnt += 1
	log.Printf("Create new listener [%d]: ok: refcnt=%d\n", port, listener.refcnt)
	d.ListenersLock.Unlock()

	return listener.Listener.Accept()
}

func (d *Daemon) Remove(port int) {
	var (
		listener *Listener
		ok       bool
	)

	d.ListenersLock.Lock()
	if listener, ok = d.Listeners[port]; ok {
		listener.refcnt -= 1
		log.Printf("Remove listener [%d]; refcnt=%d\n", port, listener.refcnt)
		if listener.refcnt == 0 {
			log.Printf("Close listener [%d]\n", port)
			listener.Listener.Close()
			delete(d.Listeners, port)
		}
	}

	d.ListenersLock.Unlock()
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
		d.TCPStreamer(conn, brh.BindInfo)
	case KCP:
	default:
		log.Println("Unknown protocol")
	}
}

func (d *Daemon) serveDNS(conn net.Conn, domain string) error {
	d.DNSListener = NewDNSListener(conn, domain)
	log.Println("SERVE DNSCNC CONNECTION")
	err := d.DNSListener.Serve()
	log.Println("DNSCNC CONNECTION FAILED: ", err)
	return err
}

func SendMessage(conn net.Conn, msg interface{}) error {
	data, err := msgpack.Marshal(msg)
	if err != nil {
		return err
	}

	var datalen int32 = int32(len(data))

	err = binary.Write(conn, binary.BigEndian, datalen)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)

	return err
}

func RecvMessage(conn net.Conn, msg interface{}) error {
	var datalen int32

	log.Println("READ LEN")
	err := binary.Read(conn, binary.BigEndian, &datalen)
	if err != nil {
		return err
	}

	log.Println("READ LEN:", datalen)
	data := make([]byte, datalen)

	_, err = io.ReadFull(conn, data)
	if err != nil {
		return err
	}

	log.Println("UNMARSHAL:", data)
	return msgpack.Unmarshal(data, msg)
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
			Addr: "0.0.0.0:5454",
			Net:  "udp",
		},
		TCPServer: &dns.Server{
			Addr: "0.0.0.0:5454",
			Net:  "tcp",
		},
		DNSRequests: make(chan *DNSRequest),
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

	defer close(tcperr)
	defer close(udperr)
	defer close(decoderr)
	defer close(recvStrings)
	defer close(recvErrors)
	defer close(closeNotify)

	go func() {
		err := p.TCPServer.ListenAndServe()
		if err != nil {
			log.Printf("Couldn't start TCP DNS listener: %s\n", err.Error())
		}

		tcperr <- err

		log.Println("DNS TCP CLOSED")
	}()

	go func() {
		err := p.UDPServer.ListenAndServe()
		if err != nil {
			log.Printf("Couldn't start UDP DNS listener: %s\n", err.Error())
		}

		udperr <- err

		log.Println("DNS UDP CLOSED")
	}()

	go func() {
		for {
			var response []string

			err := RecvMessage(p.Conn, &response)
			if err != nil || response == nil {
				recvErrors <- err
				break
			} else {
				recvStrings <- response
			}
		}

		log.Println("REMOTE READER CLOSED")
	}()

	go func() {
		ignore := false

		for {
			var (
				err error
				r   *DNSRequest
			)

			select {
			case r = <-p.DNSRequests:
			case err = <-recvErrors:
				decoderr <- err
				break
			}

			if r == nil {
				closeNotify <- true
				break
			}

			if ignore {
				r.IPs <- []string{}
				continue
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
			case err = <-recvErrors:
				r.IPs <- []string{}
				decoderr <- err
				ignore = true
			}
		}

		log.Println("DNS READ/WRITE CLOSED")
	}()

	var err error

	tcpClosed := false
	udpClosed := false
	decoderClosed := false
	shutdown := false

	for !(tcpClosed && udpClosed && decoderClosed) {
		var err2 error
		select {
		case err2 = <-tcperr:
			tcpClosed = true

		case err2 = <-udperr:
			udpClosed = true

		case err2 = <-decoderr:
			decoderClosed = true

		case <-closeNotify:
			shutdown = true
			decoderClosed = true
		}

		if !shutdown {
			p.Shutdown()
			shutdown = true
		}

		if err == nil {
			err = err2
		}

		log.Println("CLOSED: ", tcpClosed, udpClosed, decoderClosed, shutdown)
	}

	return err
}

func (p *DNSListener) Shutdown() {
	p.UDPServer.Shutdown()
	p.TCPServer.Shutdown()
	close(p.DNSRequests)
}

func netReader(conn net.Conn, ch chan []byte, cherr chan error) {
	var buffer [65535]byte
	for {
		n, err := conn.Read(buffer[:])
		if n > 0 {
			ch <- buffer[:n]
		}

		if err != nil {
			log.Println("Flush close")
			ch <- nil
			log.Println("Flush error")
			cherr <- err
			log.Println("Flushed")
			break
		}
	}

	log.Println("netReader exited!")
}

func netForwarder(local, remote net.Conn, errout chan error, out chan []byte) (error, error) {
	in := make(chan []byte)
	errin := make(chan error)

	defer close(errin)
	defer close(in)

	go netReader(remote, in, errin)

	localAddr := strings.Split(local.LocalAddr().String(), ":")
	remoteAddr := strings.Split(remote.RemoteAddr().String(), ":")

	localPort, _ := strconv.Atoi(localAddr[1])
	remotePort, _ := strconv.Atoi(remoteAddr[1])

	log.Println("Report forwarder started")
	SendMessage(local, ConnectionAcceptHeader{
		LocalHost:  localAddr[0],
		LocalPort:  localPort,
		RemoteHost: remoteAddr[0],
		RemotePort: remotePort,
	})

	var (
		err  error
		data []byte
		to   net.Conn
	)

	for {
		select {
		case data = <-in:
			to = local
			if data == nil {
				in = nil
				remote.Close()
			}

		case data = <-out:
			to = remote
			if data == nil {
				out = nil
				local.Close()
			}
		}

		if data == nil {
			to.Close()
		} else {
			_, err = to.Write(data)
			if err != nil {
				if out != nil {
					local.Close()
				}

				if in != nil {
					remote.Close()
				}
				log.Println("Send error: ", err)
			}
		}

		if in == nil && out == nil {
			log.Println("Both sides are down")
			break
		}
	}

	log.Println("FORWARD COMPLETED")
	err1 := <-errin
	log.Println("ERROR MESSAGES PASSED / ERRIN")
	return err, err1
}

func KCPStreamer(addr string) {
	ll, err := kcp.Listen(":1234")
	if err != nil {
		log.Println("Error: ", err)
	}

	l := ll.(*kcp.Listener)

	l.SetReadBuffer(8192)

	conn, err := l.AcceptKCP()
	if err != nil {
		log.Println("Accept Error: ", err)
	}

	log.Println("ACCEPT!")

	buffer := make([]byte, 8192)

	for {
		n, err := conn.Read(buffer)
		log.Println("data: ", string(buffer[:n]), err)
	}
}

func (d *Daemon) TCPStreamer(in net.Conn, bind string) {
	defer in.Close()

	port, err := strconv.Atoi(bind)
	if err != nil {
		log.Println("Invalid port: ", err.Error())
		SendMessage(in, ConnectionAcceptHeader{
			Error: err.Error(),
		})
		return
	}

	errout := make(chan error)
	out := make(chan []byte)

	chconn := make(chan net.Conn)
	cherror := make(chan error)

	defer close(errout)
	defer close(out)
	defer close(cherror)
	defer close(chconn)

	go netReader(in, out, errout)

	go func() {
		conn, err := d.Accept(port, func() (net.Listener, error) {
			log.Println("New listener requested, port:", port)
			return net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
		})

		log.Println("Accepted connection")

		if err != nil || conn == nil {
			log.Println("Accept failed: ", err.Error())
			SendMessage(in, ConnectionAcceptHeader{
				Error: err.Error(),
			})

			log.Println("Acceptor flushed error")
			cherror <- err
			log.Println("Acceptor exited")
			return
		} else {
			chconn <- conn
		}

		log.Println("Acceptor completed")
	}()

	needFinishAcceptor := true

	select {
	case conn := <-chconn:
		log.Println("Starting forwarder..")
		err1, err2 := netForwarder(in, conn, cherror, out)
		log.Println("Wait for out forwarder error")
		err3 := <-errout
		log.Println("Forwarder error: ", err1, err2, err3)

		needFinishAcceptor = false

	case _ = <-out:
		<-errout

	case err := <-cherror:
		log.Println("Error during accept: ", err.Error())

		needFinishAcceptor = false
	}

	d.Remove(port)

	if needFinishAcceptor {
		log.Println("Need finish acceptor!")
		<-cherror
		log.Println("Need finish acceptor - done")
	}

	pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
}

func init() {
	n, err := rand.Read(PSK[:])
	if n != len(PSK) || err != nil {
		panic("Couln't generate PSK")
	}

	log.Println("PSK:", hex.EncodeToString(PSK[:]))
}

func main() {
	NewDaemon("0.0.0.0:9876").ListenAndServe()
}
