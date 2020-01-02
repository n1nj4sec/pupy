# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
__all__ = (
    'Echo', 'echo'
)


from random import choice, shuffle
from time import time
from socket import socket, SOCK_DGRAM, AF_INET
from select import select
from string import letters
from threading import Thread, Lock, Event
from netaddr import IPAddress
from urllib2 import (
    OpenerDirector, HTTPHandler, Request
)

from network.lib.scan import scan, TOP1000
from network.lib.tinyhttp import NullHandler


MAGIC = b'\xDE\xAD\xBE\xEF'
USER_AGENT = 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)'


class EchoScanHTTP(object):
    __slots__ = (
        'available',

        '_timeout',
        '_check_again', '_table', '_opener', '_lock'
    )

    def __init__(self, timeout=10):
        self.available = set()

        self._table = {}
        self._lock = Lock()

        self._timeout = timeout

        self._opener = OpenerDirector()
        self._opener.handlers = []
        self._opener.add_handler(NullHandler(self._table, self._lock))
        self._opener.add_handler(HTTPHandler())

    def _add_table(self, key, sock):
        with self._lock:
            self._table[key] = sock
            sock.setblocking(1)
            sock.settimeout(self._timeout)

    def _del_table(self, key):
        with self._lock:
            del self._table[key]

    def on_open_port(self, info):
        host, port, sock = info
        key = '{}:{}'.format(host, port)
        try:
            self._add_table(key, sock)

            request = Request(
                'http://{}:{}/?echo=%DE%AD%BE%EF'.format(host, port),
                headers={
                    'Host': key,
                    'User-Agent': USER_AGENT,
                })

            response = self._opener.open(
                request, timeout=self._timeout
            )
            data = response.read()

            if data.startswith('GET /?echo=%DE%AD%BE%EF'):
                self.available.add(port)

        finally:
            sock.close()
            self._del_table(key)


class EchoScanTcp(object):
    __slots__ = (
        'available', 'timeout'
    )

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.available = set()

    def on_open_port(self, info):
        host, port, sock = info
        try:
            sock.setblocking(1)
            sock.settimeout(self.timeout)

            payload = MAGIC + b''.join(
                choice(letters) for i in xrange(64))

            sock.send(payload)
            response = sock.recv(len(payload))

            if response == payload:
                self.available.add(port)

        finally:
            sock.close()


def udp(host, timeout=10, amount=10, abort=None):
    connectable_udp = set()

    top_ports = range(20000, 65535)
    low_ports = range(1, 20000)

    shuffle(top_ports)
    shuffle(low_ports)

    ports = iter(top_ports + low_ports)
    more = True

    datas = {}

    while (more or datas) and (not abort or not abort.is_set()):
        while more and len(datas) < 32:
            try:
                port = next(ports)
            except StopIteration:
                more = False
                break

            s = socket(AF_INET, SOCK_DGRAM)
            s.connect((host, port))

            payload = MAGIC + ''.join(
                choice(letters) for i in xrange(64))

            datas[s] = (port, payload, time())
            try:
                s.send(payload)
            except (OSError, IOError):
                del datas[s]

        r, _, _ = select(datas.keys(), [], [], timeout)
        for sock in r:
            port, inital_payload, _ = datas[sock]
            try:
                payload = sock.recv(len(inital_payload))
                if payload == inital_payload:
                    connectable_udp.add(port)

            except (IOError, OSError):
                pass

            finally:
                del datas[sock]
                sock.close()

        to_cleanup = []
        now = time()

        for sock, (_, _, start) in datas.iteritems():
            if now - start > timeout:
                to_cleanup.append(sock)

        for sock in to_cleanup:
            sock.close()
            del datas[sock]

        if len(connectable_udp) > amount:
            break

    return connectable_udp


def tcp(host, timeout=10, amount=10, abort=None):
    http_context = EchoScanHTTP(timeout)
    tcp_context = EchoScanTcp(timeout)

    top_ports = list(TOP1000)
    low_ports = list(x for x in xrange(1, 65535) if x not in top_ports)

    shuffle(top_ports)
    shuffle(low_ports)

    ports = top_ports + low_ports

    chunk = min(amount, 32)

    while ports and len(http_context.available) < amount:
        portion, ports = ports[:chunk], ports[chunk:]

        portion = scan(
            [host], portion,
            abort=abort, timeout=timeout,
            on_open_port=http_context.on_open_port,
            pass_socket=True
        )

        conntable = (port for _, port in portion)

        scan(
            [host], conntable,
            abort=abort, timeout=timeout,
            on_open_port=tcp_context.on_open_port,
            pass_socket=True
        )

    connectable_raw = tcp_context.available
    connectable_http = set(
        port for port in http_context.available
        if port not in tcp_context.available
    )

    return connectable_raw, connectable_http


class Echo(Thread):
    __slots__ = (
        '_abort', 'tcp', 'http', 'udp',
        'amount', 'host',

        '_on_complete',
    )

    def __init__(self, host, amount=8, on_complete=None):
        Thread.__init__(self)
        self.daemon = True
        self.host = IPAddress(host)
        self.amount = amount
        self._abort = Event()

        self.tcp = None
        self.http = None
        self.udp = None

        self._on_complete = on_complete

    def abort(self):
        self._abort.set()

    def run(self):
        self.tcp, self.http = tcp(
            str(self.host),
            amount=self.amount,
            abort=self._abort
        )

        self.udp = udp(
            str(self.host),
            amount=self.amount,
            abort=self._abort
        )

        if self._on_complete:
            self._on_complete(
                self.tcp, self.http, str(self.udp)
            )


def echo(host, amount, on_complete):
    echo = Echo(host, amount, on_complete)
    echo.start()
    return echo.abort
