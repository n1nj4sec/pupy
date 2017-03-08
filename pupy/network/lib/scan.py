# -*- coding: utf-8 -*-

import socket
import select
import errno
import time
import threading
import rpyc
import logging

def chunks(l, n):
    chunk = []
    for i in l:
        if len(chunk) == n:
            yield chunk
            chunk = []
        else:
            chunk.append(i)

    if chunk:
        yield chunk

def create_socket(host, port):
    sock = socket.socket()
    sock.setblocking(0)
    try:
        r = sock.connect_ex((host, int(port)))
    except Exception, e:
        print "Exception: {}/{}".format(e, type(e))
        return None, None
    return sock, r

def scan(hosts, ports, abort=None, timeout=10, portion=32, on_complete=None, on_open_port=None):
    connectable=[]
    for portion in chunks(((x, y) for x in hosts for y in ports), portion):
        if not portion:
            continue

        if abort and abort.is_set():
            break

        sockets = {}
        for host, port in portion:
            sock, r = create_socket(host, port)
            if sock is None:
                continue

            if r:
                ok = [errno.EAGAIN, errno.EINPROGRESS]
                if 'WSAEWOULDBLOCK' in errno.__dict__:
                    ok.append(errno.WSAEWOULDBLOCK)

                if r in ok:
                    sockets[sock] = (host, port)
                else:
                    sock.close()
                    continue
            else:
                if on_open_port:
                    on_open_port((host, port))

                connectable.append((host, port))
                sock.close()

        if sockets:
            start = time.time()
            while sockets and time.time() - start < timeout:
                socks = list(sockets.iterkeys())
                _, w, _ = select.select([], socks, [], timeout - (time.time() - start))

                for sock in w:
                    try:
                        errcode = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                        if errcode == 0:
                            if on_open_port:
                                on_open_port(sockets[sock])

                            connectable.append(sockets[sock])
                    except:
                        pass

                    finally:
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
