package main

import (
	"log"

	"fmt"
	"net"
	"strconv"
	"strings"

	"errors"

	kcp "github.com/xtaci/kcp-go"
)

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
			n, err := to.Write(data)
			log.Println("Write: ", n)
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

func (d *Daemon) listenAcceptTCP(port int, cherr chan error, chconn chan net.Conn) {
	conn, err := d.Accept(port, func() (net.Listener, error) {
		log.Println("New listener requested, port:", port)
		return net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	})

	log.Println("Accepted connection")

	if err != nil || conn == nil {
		log.Println("Acceptor flushed error")
		cherr <- err
		log.Println("Acceptor exited")
		return
	} else {
		chconn <- conn
	}

	log.Println("Acceptor completed")
}

func (d *Daemon) listenAcceptKCP(port int, cherr chan error, chconn chan net.Conn) {
	conn, err := d.Accept(port, func() (net.Listener, error) {
		log.Println("New KCP listener requested, port:", port)

		ll, err := kcp.Listen(fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			log.Println("Error: ", err)
			return nil, err
		}

		l := ll.(*kcp.Listener)

		l.SetReadBuffer(8192)
		return l, nil
	})

	log.Println("Accepted connection")

	if err != nil || conn == nil {
		log.Println("Acceptor flushed error")
		cherr <- err
		log.Println("Acceptor exited")
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
	log.Println("Acceptor completed (KCP)")
}

func (d *Daemon) serveStream(in net.Conn, bind string, acceptor func(int, chan error, chan net.Conn)) {
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
	cherr := make(chan error)

	defer close(errout)
	defer close(out)
	defer close(cherr)
	defer close(chconn)

	go netReader(in, out, errout)
	go acceptor(port, cherr, chconn)

	needFinishAcceptor := true

	select {
	case conn := <-chconn:
		log.Println("Starting forwarder..")
		err1, err2 := netForwarder(in, conn, cherr, out)
		log.Println("Wait for out forwarder error")
		err3 := <-errout
		log.Println("Forwarder error: ", err1, err2, err3)

		needFinishAcceptor = false

	case _ = <-out:
		<-errout

	case err := <-cherr:
		log.Println("Error during accept: ", err.Error())
		SendMessage(in, ConnectionAcceptHeader{
			Error: err.Error(),
		})

		<-out
		<-errout

		needFinishAcceptor = false
	}

	d.Remove(port)

	if needFinishAcceptor {
		log.Println("Need finish acceptor!")
		<-cherr
		log.Println("Need finish acceptor - done")
	}
}
