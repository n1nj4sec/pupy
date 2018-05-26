package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"time"

	"errors"

	"crypto/tls"
	"crypto/x509"

	log "github.com/sirupsen/logrus"
	kcp "github.com/xtaci/kcp-go"
)

func netReader(mtu int, conn net.Conn, ch chan []byte, cherr chan error) {
	buffers := [][]byte{
		make([]byte, 65535),
		make([]byte, 65535),
	}

	buffIdx := 0

	for {
		buffer := buffers[buffIdx]
		n, err := conn.Read(buffer)

		if n > 0 {
			if n < mtu || mtu == -1 {
				ch <- buffer[:n]
			} else {
				offset := 0
				for n > 0 {
					portion := n
					if n > mtu {
						portion = mtu
					}

					ch <- buffer[offset : offset+portion]
					n -= portion
					offset += portion
				}
			}
			buffIdx = (buffIdx + 1) % 2
		}

		if err != nil {
			log.Debug("Flush close")
			ch <- nil
			log.Debug("Flush error")
			cherr <- err
			log.Debug("Flushed")
			break
		}
	}

	log.Debug("netReader exited!")
}

func netForwarder(local, remote net.Conn, errout chan error, out chan []byte) (error, error) {
	in := make(chan []byte)
	errin := make(chan error)

	defer close(errin)
	defer close(in)

	go netReader(-1, remote, in, errin)

	localAddr := strings.Split(remote.LocalAddr().String(), ":")
	remoteAddr := strings.Split(remote.RemoteAddr().String(), ":")

	localPort, _ := strconv.Atoi(localAddr[1])
	remotePort, _ := strconv.Atoi(remoteAddr[1])

	log.Warning("Accept: ", remote.LocalAddr(), " <- ", remote.RemoteAddr())
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
			_, err := to.Write(data)
			if err != nil {
				if out != nil {
					local.Close()
				}

				if in != nil {
					remote.Close()
				}
				log.Warning("Send error: ", err)
			}
		}

		if in == nil && out == nil {
			log.Debug("Both sides are down")
			break
		}
	}

	log.Debug("FORWARD COMPLETED")
	err1 := <-errin
	log.Debug("ERROR MESSAGES PASSED / ERRIN")
	log.Info("Closed: ", remoteAddr)
	return err, err1
}

func (d *Daemon) Accept(in net.Conn, port int, cherr chan error, createListener func(net.Conn) (net.Listener, error)) (net.Conn, error) {
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

	cherr <- nil
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

func (d *Daemon) listenAcceptTCP(in net.Conn, port int, cherr chan error, chconn chan net.Conn) {
	conn, err := d.Accept(in, port, cherr, func(in net.Conn) (net.Listener, error) {
		log.Println("New listener requested, port:", port)
		return net.Listen("tcp", fmt.Sprintf("%s:%d", ExternalBindHost, port))
	})

	log.Debug("TCP: Accepted connection")

	if err != nil || conn == nil {
		log.Debug("Acceptor flushed error")
		cherr <- err
		log.Debug("Acceptor exited")
		return
	} else {
		conn.(*net.TCPConn).SetKeepAlive(true)
		conn.(*net.TCPConn).SetKeepAlivePeriod(1 * time.Minute)
		conn.(*net.TCPConn).SetNoDelay(true)

		chconn <- conn
	}

	log.Debug("Acceptor completed")
}

func (d *Daemon) listenAcceptTLS(in net.Conn, port int, cherr chan error, chconn chan net.Conn) {
	conn, err := d.Accept(in, port, cherr, func(in net.Conn) (net.Listener, error) {
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

	log.Debug("SSL: Accepted connection")

	if err != nil || conn == nil {
		log.Debug("Acceptor flushed error")
		cherr <- err
		log.Debug("Acceptor exited")
		return
	} else {
		chconn <- conn
	}

	log.Debug("Acceptor completed")
}

func (d *Daemon) listenAcceptKCP(in net.Conn, port int, cherr chan error, chconn chan net.Conn) {
	conn, err := d.Accept(in, port, cherr, func(in net.Conn) (net.Listener, error) {
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

	log.Debug("Accepted connection")

	if err != nil || conn == nil {
		log.Debug("Acceptor flushed error")
		cherr <- err
		log.Debug("Acceptor exited")
		return
	}

	pupyKCPpreamble := make([]byte, 512)

	n, err := conn.Read(pupyKCPpreamble)
	if err != nil {
		conn.Close()
		cherr <- errors.New("preamble failed")
		return
	}

	if n != 512 {
		conn.Close()
		cherr <- errors.New(fmt.Sprintf("invalid preamble size=%d", n))
		return
	}

	for _, c := range pupyKCPpreamble {
		if c != 0x0 {
			conn.Close()
			cherr <- errors.New("invalid preamble")
			return
		}
	}

	_, err = conn.Write(pupyKCPpreamble)
	if err != nil {
		conn.Close()
		cherr <- errors.New("preamble communication failed")
		return
	}

	chconn <- conn
	log.Debug("Acceptor completed (KCP)")
}

func (d *Daemon) serveStream(mtu int, in net.Conn, bind string,
	acceptor func(net.Conn, int, chan error, chan net.Conn)) {

	defer in.Close()

	port, err := strconv.Atoi(bind)
	if err != nil {
		log.Error("Invalid port: ", err.Error())
		SendMessage(in, ConnectionAcceptHeader{
			Error: err.Error(),
		})
		return
	}

	errout := make(chan error)
	out := make(chan []byte)

	chconn := make(chan net.Conn)
	cherr := make(chan error)

	defer close(errout)
	defer close(out)
	defer close(cherr)
	defer close(chconn)

	for _, mapping := range PortMaps {
		if port == mapping.From {
			port = mapping.To
			break
		}
	}

	go acceptor(in, port, cherr, chconn)

	needFinishAcceptor := true

	prepared := <-cherr
	if prepared != nil {
		log.Error("Acceptor preparation failed:", prepared)
		return
	}

	go netReader(mtu, in, out, errout)

	select {
	case conn := <-chconn:
		log.Debug("Starting forwarder..")
		err1, err2 := netForwarder(in, conn, cherr, out)
		log.Debug("Wait for out forwarder error")
		err3 := <-errout
		log.Info("Forwarder error: ", err1, err2, err3)

		needFinishAcceptor = false

	case _ = <-out:
		<-errout

	case err := <-cherr:
		log.Error("Error during accept: ", err.Error())
		SendMessage(in, ConnectionAcceptHeader{
			Error: err.Error(),
		})

		<-out
		<-errout

		needFinishAcceptor = false
	}

	d.Remove(port)

	if needFinishAcceptor {
		log.Debug("Need finish acceptor!")
		<-cherr
		log.Debug("Need finish acceptor - done")
	}
}
