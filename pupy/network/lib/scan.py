# -*- coding: utf-8 -*-

import socket
import select
import errno
import time
import threading
import rpyc

def chunks(l, n):
    for i in xrange(0, len(l), n):
        yield l[i:i + n]

def create_socket(host, port):
    sock = socket.socket()
    sock.setblocking(0)
    r = sock.connect_ex((host, port))
    return sock, r

def scan(host, ports, abort=None, timeout=10, portion=32, on_complete=None):
    connectable=[]
    for portion in chunks(list(ports), portion):
        if not portion:
            continue

        if abort and abort.is_set():
            break

        sockets = {}
        for port in portion:
            sock, r = create_socket(host, port)
            if r:
                if r in (errno.EAGAIN, errno.EINPROGRESS):
                    sockets[sock] = port
                else:
                    sock.close()
                    continue
            else:
                connectable.append(port)
                sock.close()

        start = time.time()
        while sockets and time.time() - start < timeout:
            socks = list(sockets.iterkeys())
            _, w, _ = select.select([], socks, [], timeout - (time.time() - start))

            for sock in w:
                errcode = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if errcode == 0:
                    connectable.append(sockets[sock])
                sock.close()
                del sockets[sock]

    if on_complete:
        if abort and not abort.is_set():
            on_complete(connectable)
    else:
        return connectable

def scanthread(host, ports, on_complete, **kwargs):
    host = str(host)
    ports = [ x for x in ports ]
    abort = threading.Event()
    connectable = []
    kwargs.update({
        'abort': abort,
        'on_complete': rpyc.async(on_complete)
    })
    scanner = threading.Thread(target=scan, args=(host, ports), kwargs=kwargs)
    scanner.daemon = True
    scanner.start()

    return abort
