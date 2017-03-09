# -*- coding: utf-8 -*-

import socket
import select
import errno
import time
import threading
import rpyc
import logging

def create_socket(host, port):
    sock = socket.socket()
    sock.setblocking(0)
    try:
        print 'Try: {}:{}'.format(host, int(port))
        r = sock.connect_ex((host, int(port)))
    except Exception, e:
        print "Exception: {}/{}".format(e, type(e))
        return None, None
    return sock, r

def scan(hosts, ports, abort=None, timeout=10, portion=32, on_complete=None, on_open_port=None):
    connectable=[]
    targets = ((x, y) for x in hosts for y in ports)
    sockets = {}
    while targets:
        free = portion - len(sockets)
        chunk = []
        while free:
            try:
                chunk.append(next(targets))
                free -= 1
            except StopIteration:
                targets = None
                break

        if abort and abort.is_set():
            break

        for host, port in chunk:
            sock, r = create_socket(host, port)
            if sock is None:
                continue

            if r:
                ok = [errno.EAGAIN, errno.EINPROGRESS]
                if 'WSAEWOULDBLOCK' in errno.__dict__:
                    ok.append(errno.WSAEWOULDBLOCK)

                if r in ok:
                    sockets[sock] = (host, port, time.time())
                else:
                    sock.close()
                    continue
            else:
                if on_open_port:
                    on_open_port((host, port))

                connectable.append((host, port))
                sock.close()

        if sockets:
            socks = list(sockets.iterkeys())
            _, w, _ = select.select([], socks, [], timeout)

            for sock in w:
                try:
                    errcode = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if errcode == 0:
                        if on_open_port:
                            on_open_port(sockets[sock][:2])

                        connectable.append(sockets[sock][:2])
                except:
                    pass

                finally:
                    sock.close()
                    del sockets[sock]

            now = time.time()
            for sock in socks:
                if sock in w:
                    continue

                if now - sockets[sock][2] > timeout:
                    sock.close()
                    del sockets[sock]


    if on_complete:
        if abort and not abort.is_set():
            on_complete(connectable)
    else:
        return connectable

def scanthread(hosts, ports, on_complete, **kwargs):
    hosts = [ x for x in hosts ]
    ports = [ x for x in ports ]
    abort = threading.Event()
    connectable = []
    kwargs.update({
        'abort': abort,
        'on_complete': rpyc.async(on_complete)
    })
    scanner = threading.Thread(target=scan, args=(hosts, ports), kwargs=kwargs)
    scanner.daemon = True
    scanner.start()

    return abort
