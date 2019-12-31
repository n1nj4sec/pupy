package main

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"time"

	"context"
	"errors"

	"crypto/tls"
	"crypto/x509"
	"math/rand"

	log "github.com/sirupsen/logrus"
	kcp "github.com/xtaci/kcp-go"
)

func NewNetReader(mtu int, in, out net.Conn) *NetReader {
	return &NetReader{
		mtu:  mtu,
		in:   in,
		out:  out,
		wait: make(chan error),
	}
}

func (n *NetReader) recv() ([]byte, error) {
	portion := 1024 * n.mtu
	if portion <= 0 {
		portion = 4 * 1024 * 1024
	}

	buffer := make([]byte, portion)
	l, err := n.in.Read(buffer)
	if err != nil {
		return nil, err
	}

	return buffer[:l], err
}

func (n *NetReader) send(buffer []byte) error {
	toSend := len(buffer)
	offset := 0

	for {
		if toSend == 0 {
			break
		}

		portion := toSend
		if n.mtu > 0 && portion > n.mtu {
			portion = n.mtu
		}

		cnt, err := n.out.Write(buffer[offset : offset+portion])
		if err != nil {
			return err
		}

		offset += cnt
		toSend -= cnt
	}

	return nil
}

func (n *NetReader) Serve() {
	for {
		buffer, err := n.recv()
		if err != nil {
			n.ReportError(err)
			return
		}

		err = n.send(buffer)
		if err != nil {
			n.ReportError(err)
			return
		}
	}
}

func (n *NetReader) ReportError(err error) {
	log.Error(
		"NetReader: ", n.in.RemoteAddr(), " -> ",
		n.out.RemoteAddr(), ": ", err,
	)

	n.err = err
	select {
	case n.wait <- err:
	default:
	}
}

func NewNetForwarder(pproxy, remote net.Conn) *NetForwarder {
	return &NetForwarder{
		pproxy: pproxy,
		remote: remote,
	}
}

func (n *NetForwarder) sendRemoteConnectionInfo() error {
	localAddr, localPortS, _ := net.SplitHostPort(n.remote.LocalAddr().String())
	remoteAddr, remotePortS, _ := net.SplitHostPort(n.remote.RemoteAddr().String())

	localPort, _ := strconv.Atoi(localPortS)
	remotePort, _ := strconv.Atoi(remotePortS)

	return SendMessage(n.pproxy, ConnectionAcceptHeader{
		LocalHost:  localAddr,
		LocalPort:  localPort,
		RemoteHost: remoteAddr,
		RemotePort: remotePort,
	})
}

func (n *NetForwarder) Serve(ctx context.Context, l7ready chan error, remoteMtu int) error {
	log.Warning(
		"Forwarder: ", n.remote.LocalAddr(), " <- ", n.remote.RemoteAddr(),
	)

	err := n.sendRemoteConnectionInfo()
	if err != nil {
		log.Error("Notification handler send failed: ", err)
		return err
	}

	select {
	case err = <-l7ready:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return errors.New("Cancelled")
	}

	log.Debug("Start network readers")

	remoteLocalReader := NewNetReader(remoteMtu, n.remote, n.pproxy)
	localRemoteReader := NewNetReader(remoteMtu, n.pproxy, n.remote)

	go remoteLocalReader.Serve()
	go localRemoteReader.Serve()

	select {
	case err = <-remoteLocalReader.wait:
		log.Debug("NetForwarder: Remote->Local Closed: ", err)
		return err

	case err = <-localRemoteReader.wait:
		log.Debug("NetForwarder: Local->Remote Closed: ", err)
		return err

	case <-ctx.Done():
		log.Debug("NetForwarder: Cancellation received")
		return errors.New("Cancelled")
	}
}

func (d *Daemon) Accept(in net.Conn, port int, createListener func(net.Conn) (net.Listener, error)) (net.Conn, error) {
	var (
		listener *Listener
		ok       bool
	)

	d.ListenersLock.Lock()
	if listener, ok = d.Listeners[port]; !ok {
		log.Debug(fmt.Sprintf("Create new listener [%d]", port))
		l, err := createListener(in)
		if err != nil {
			log.Error(fmt.Sprintf("Create new listener [%d]: failed: %s", port, err.Error()))
			d.ListenersLock.Unlock()
			return nil, err
		}

		listener = &Listener{
			Listener: l,
			refcnt:   0,
		}

		d.Listeners[port] = listener
		log.Debug(fmt.Sprintf("New listener [%d] created", port))
	}

	listener.refcnt += 1
	log.Info(fmt.Sprintf("Create new listener [%d]: ok: refcnt=%d", port, listener.refcnt))
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
		log.Info(fmt.Sprintf("Remove listener [%d]; refcnt=%d", port, listener.refcnt))
		if listener.refcnt == 0 {
			log.Info(fmt.Sprintf("Close listener [%d]", port))
			listener.Listener.Close()
			delete(d.Listeners, port)
		}
	}

	d.ListenersLock.Unlock()
}

func (d *Daemon) listenAcceptTCP(in net.Conn, port int) (net.Conn, error) {
	conn, err := d.Accept(in, port, func(in net.Conn) (net.Listener, error) {
		log.Println("New listener requested, port:", port)
		return net.Listen("tcp", fmt.Sprintf("%s:%d", ExternalBindHost, port))
	})

	log.Debug("TCP: Accepted connection")

	if conn != nil {
		conn.(*net.TCPConn).SetKeepAlive(true)
		conn.(*net.TCPConn).SetKeepAlivePeriod(1 * time.Minute)
		conn.(*net.TCPConn).SetNoDelay(true)
	}

	log.Debug("TCP Acceptor completed: ", conn, err)
	return conn, err
}

func (d *Daemon) listenAcceptTLS(in net.Conn, port int) (net.Conn, error) {
	conn, err := d.Accept(in, port, func(in net.Conn) (net.Listener, error) {
		log.Debug("Load certificates")
		err := SendMessage(in, &Extra{
			Extra: true,
			Data:  "certs",
		})
		if err != nil {
			return nil, err
		}

		config := &TLSAcceptorConfig{}
		err = RecvMessage(in, config)
		if err != nil {
			log.Error("Couldn't receive TLS certificate")
			return nil, err
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(config.CACert)) {
			log.Error("Invalid CA cert")
			return nil, errors.New("Invalid CA cert")
		}

		cert, err := tls.X509KeyPair([]byte(config.Cert), []byte(config.Key))
		if err != nil {
			log.Error("Invalid SSL Key/Cert")
			return nil, errors.New("Invalid SSL Key/Cert: " + err.Error())
		}

		log.Debug("SSL: New listener requested, port:", port)
		return tls.Listen("tcp", fmt.Sprintf("%s:%d", ExternalBindHost, port), &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		})
	})

	log.Debug("SSL: Accepted connection: ", conn, err)
	return conn, err
}

func NewKCPConn(in net.Conn) net.Conn {
	localId := [4]byte{}
	for i := 0; i < 4; i++ {
		localId[i] = byte(rand.Intn(255))
	}

	kcpconn := &KCPConn{
		localId: localId,
		Conn:    in,
	}
	return kcpconn
}

func (c *KCPConn) sendEOF() {
	end := [5]byte{}
	end[0] = KCP_END
	copy(end[1:], c.localId[:])
	c.Conn.Write(end[:])
}

func compareId(id1, id2 []byte) bool {
	if len(id1) != 4 || len(id2) != 4 {
		return false
	}

	for i := 0; i < 4; i++ {
		if id1[i] != id2[i] {
			return false
		}
	}

	return true
}

func (c *KCPConn) Read(b []byte) (n int, err error) {
	buf := make([]byte, len(b)+5)

	n, err = c.Conn.Read(buf)

	if err != nil || n < 5 {
		log.Debug(
			"KCP: Invalid KCP header (too small or error) ",
			n, err,
		)
		return 0, io.EOF
	}

	switch buf[0] {
	case KCP_NEW:
		if !c.initialized {
			log.Debug("KCP: NEW received")
			copy(c.remoteId[:], buf[1:5])
			c.initialized = true
		} else {
			log.Debug("KCP: Unexpected NEW")
			c.sendEOF()
			return 0, io.EOF
		}
	case KCP_DAT:
		if !c.initialized || !compareId(c.remoteId[:], buf[1:5]) {
			log.Debug("KCP: Unexpected DAT")
			c.sendEOF()
			return 0, io.EOF
		}
	case KCP_END:
		log.Debug("KCP: EOF Received")
		return 0, io.EOF

	default:
		log.Debug("KCP: Unknown flag")
		return 0, io.EOF
	}

	return copy(b[:], buf[5:n]), nil
}

func (c *KCPConn) Write(b []byte) (n int, err error) {
	buf := make([]byte, len(b)+5)
	if c.new_sent {
		buf[0] = KCP_DAT
	} else {
		buf[0] = KCP_NEW
		c.new_sent = true
	}

	copy(buf[1:5], c.localId[:])
	copy(buf[5:], b[:])

	n, err = c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}

	return n - 5, nil
}

func (c *KCPConn) Close() error {
	log.Debug("KCP: Close() called, send EOF")
	c.sendEOF()
	return c.Conn.Close()
}

func (c *KCPConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *KCPConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *KCPConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *KCPConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *KCPConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (d *Daemon) listenAcceptKCP(in net.Conn, port int) (net.Conn, error) {
	conn, err := d.Accept(in, port, func(in net.Conn) (net.Listener, error) {
		log.Debug("New KCP listener requested, port:", port)

		ll, err := kcp.Listen(fmt.Sprintf("%s:%d", ExternalBindHost, port))
		if err != nil {
			log.Error("KCP Listen Error: ", err)
			return nil, err
		}

		l := ll.(*kcp.Listener)

		l.SetReadBuffer(1024 * 1024)
		l.SetWriteBuffer(1024 * 1024)
		return l, nil
	})

	log.Debug("KCP: Accepted connection", conn, err)
	return NewKCPConn(conn), err
}

func l7KeepAliveSender(ctx context.Context, conn net.Conn, cherr chan error) {
	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case t := <-ticker.C:
			err := SendKeepAlive(conn, t)
			if err != nil {
				select {
				case cherr <- err:
				default:
				}
				return
			}
		}
	}
}

func l7KeepAliveReceiver(ctx context.Context, conn net.Conn, cherr chan error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			keepalive := &KeepAlive{}
			err := RecvMessage(conn, keepalive)
			if err != nil {
				select {
				case cherr <- err:
				default:
				}
				return
			}

			rtt := time.Now().Unix() - keepalive.Tick

			log.Debug(
				"KeepAlive: ", keepalive.Tick,
				" RTT: ", rtt,
				" Last: ", keepalive.Last)

			if keepalive.Last {
				select {
				case cherr <- nil:
				default:
				}
			}
		}
	}
}

func withAccept(
	in net.Conn, port int,
	acceptor func(net.Conn, int) (net.Conn, error),
	chconn chan net.Conn, cherr chan error) {
	conn, err := acceptor(in, port)

	if err != nil {
		select {
		case cherr <- err:
		default:
		}
	} else {
		select {
		case chconn <- conn:
		default:
		}
	}
}

func acceptOrWait(
	in net.Conn, port int,
	acceptor func(net.Conn, int) (net.Conn, error)) (chan error, net.Conn, error) {

	chconn := make(chan net.Conn)
	cherr := make(chan error)
	l7rcherr := make(chan error)

	pingContext, pingCancel := context.WithCancel(context.Background())
	defer pingCancel()

	pingRecvContext, pingRecvCancel := context.WithCancel(
		context.Background())

	defer pingRecvCancel()

	go withAccept(in, port, acceptor, chconn, cherr)
	go l7KeepAliveSender(pingContext, in, cherr)
	go l7KeepAliveReceiver(pingRecvContext, in, l7rcherr)

	select {
	case conn := <-chconn:
		return l7rcherr, conn, nil
	case err := <-l7rcherr:
		log.Error("L7 KeepAlive Receiver failed for ", in.RemoteAddr())
		return nil, nil, err
	case err := <-cherr:
		log.Error("Accept failed for ", in.RemoteAddr())
		return nil, nil, err
	}
}

func (d *Daemon) serveStream(
	mtu int, pproxy net.Conn, bind string,
	acceptor func(net.Conn, int) (net.Conn, error),
) {

	defer pproxy.Close()

	port, err := strconv.Atoi(bind)
	if err != nil {
		log.Error("Invalid port: ", err.Error())
		SendError(pproxy, err)
		return
	}

	for _, mapping := range PortMaps {
		if port == mapping.From {
			port = mapping.To
			break
		}
	}

	defer d.Remove(port)

	done, remote, err := acceptOrWait(pproxy, port, acceptor)
	if err != nil {
		SendError(pproxy, err)
		return
	}

	defer remote.Close()

	forwarder := NewNetForwarder(pproxy, remote)
	forwarder.Serve(context.Background(), done, mtu)
}
