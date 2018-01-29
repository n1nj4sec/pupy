# -*- encoding: utf-8 -*-

import msgpack
import threading
import socket
import struct
import hashlib
import logging

class MsgPackMessages(object):
    def __init__(self, conn):
        self._conn = conn

    def recv(self):
        datalen_b = self._conn.recv(4)
        datalen, = struct.unpack('>I', datalen_b)
        data = self._conn.recv(datalen)
        return msgpack.loads(data)

    def send(self, msg):
        data = msgpack.dumps(msg)
        datalen = len(data)
        datalen_b = struct.pack('>I', datalen)
        self._conn.send(datalen_b + data)

class PupyOffloadDNS(threading.Thread):
    def __init__(self, manager, handler, domain):
        threading.Thread.__init__(self)
        self.daemon = True
        self.active = True
        self.manager = manager
        self.handler = handler
        self.domain = domain
        self._conn = None

        self.cleaner = threading.Thread(target=handler.cleanup)
        self.cleaner.daemon = True

    def run(self):
        print "RUN"

        self.cleaner.start()

        try:
            while self.active:
                print "SERVE"
                self._serve()

        except Exception, e:
            print "EXCEPTION"
            logging.exception(e)
            self.active = False

    def _serve(self):
        self._conn = self.manager._connect(0, self.domain)
        conn = MsgPackMessages(self._conn)
        while self.active:
            request = conn.recv()
            if not request:
                return

            print "REQUEST:", request
            response = self.handler.process(request)
            print "RESPONSE:", response
            conn.send(response)

    def stop(self):
        print "STOP"
        self.active = False
        if self._conn:
            self._conn.close()

        if self.handler:
            self.handler.finished.set()

class PupyOffloadSocket(object):
    def __init__(self, sock, lhost, lport, rhost, rport):
        self._sock = sock
        self._laddr = (lhost, lport)
        self._raddr = (rhost, rport)

    def getsockname(self):
        return self._laddr

    def getpeername(self):
        return self._raddr

    def __getattr__(self, attr):
        if attr in self.__dict__:
            return getattr(self, attr)
        return getattr(self._sock, attr)

class PupyOffloadAcceptor(object):
    def __init__(self, manager, proto, port=None):
        self._manager = manager
        self._proto = proto
        self._host = None
        self._port = port
        self._conn = None

    def bind(self, addr):
        self._host, self._port = addr

    def listen(self, cnt):
        pass

    def settimeout(self, **args):
        pass

    def shutdown(self, arg):
        self.close()

    def close(self, **args):
        if self._conn:
            self._conn.close()
            self._conn = None

    def accept(self):
        print "ACCEPT START", self._port
        try:
            self._conn = self._manager._connect(self._proto, self._port)
            m = MsgPackMessages(self._conn)
            conninfo = m.recv()
            print "CONNINFO: ", conninfo

            return PupyOffloadSocket(
                self._conn,
                conninfo['lhost'], conninfo['lport'],
                conninfo['rhost'], conninfo['rport']
            ), (conninfo['rhost'], conninfo['rport'])

        except Exception, e:
            logging.exception(e)
            raise

class PupyOffloadManager(object):
    def __init__(self, server, psk):
        if ':' in server:
            host, port = server.rsplit(':', 1)
            self._server = (host, int(port))
        else:
            self._server = server

        self._psk = psk

    def dns(self, handler, domain):
        return PupyOffloadDNS(self, handler, domain)

    def tcp(self, port):
        return PupyOffloadAcceptor(self, 1, port=port)

    def kcp(self, port):
        return PupyOffloadAcceptor(self, 2, port=port)

    def _connect(self, conntype, bind, timeout=0):
        c = socket.create_connection(self._server)
        m = MsgPackMessages(c)
        nonce = m.recv()
        m.send({
            'nonce': hashlib.sha256(nonce + self._psk).digest(),
            'prot': conntype,
            'bind': str(bind),
            'timeout': timeout,
        })
        return c
