# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from rpyc.utils.server import ThreadPoolServer
from rpyc.core import Channel, Connection
from rpyc.utils.authenticators import AuthenticationError
from rpyc.core.stream import Stream
from buffer import Buffer
import threading, socket
from streams.PupySocketStream import addGetPeer
import logging


class PseudoStreamDecoder(Stream):
    def __init__(self, transport_class, transport_kwargs):
        self.bufin=Buffer(transport_func=addGetPeer(("127.0.0.1", 443)))
        self.bufout=Buffer(transport_func=addGetPeer(("127.0.0.1", 443)))
        self.upstream=Buffer(transport_func=addGetPeer(("127.0.0.1", 443)))
        self.downstream=Buffer(transport_func=addGetPeer(("127.0.0.1", 443)))
        self.transport=transport_class(self, **transport_kwargs)
        self.lockin=threading.Lock()
        self.lockout=threading.Lock()

    def decode_data(self, data):
        with self.lockin:
            #print "decoding %s"%repr(data)
            self.bufin.drain()
            self.bufin.write(data)
            self.transport.downstream_recv(self.bufin)
            cookie=self.bufin.cookie
            self.bufin.cookie=None
            return self.upstream.read(), cookie

    def encode_data(self, data, cookie):
        with self.lockout:
            #print "encoding %s"%repr(data)
            self.bufout.drain()
            self.bufout.write(data)
            self.bufout.cookie=cookie
            self.transport.upstream_recv(self.bufout)
            return self.downstream.read()

class PupyAsyncServer(object):
    def __init__(self, service, **kwargs):
        if not "stream" in kwargs:
            raise ValueError("missing stream_class argument")
        if not "transport" in kwargs:
            raise ValueError("missing transport argument")
        self.stream_class=kwargs["stream"]
        self.transport_class=kwargs["transport"]
        self.transport_kwargs=kwargs["transport_kwargs"]
        del kwargs["stream"]
        del kwargs["transport"]
        del kwargs["transport_kwargs"]

        self.authenticator=kwargs.get("authenticator", None)
        self.protocol_config=kwargs.get("protocol_config", {})
        self.service=service

        self.active=False
        self.clients={}
        self.void_stream=PseudoStreamDecoder(self.transport_class, self.transport_kwargs)

    def dispatch_data(self, data_received, host=None, port=None):
        """ receive data, forward it to the stream and send back the stream downstream if any """
        decoded, cookie=self.void_stream.decode_data(data_received)
        if cookie is None:
            logging.debug("failed to retreived cookie, rejecting data %s"%repr(data_received))
            return self.void_stream.encode_data("", None)
        if cookie not in self.clients:
            logging.info("new client connected : %s:%s cookie=%s"%(host, port, cookie))
            config = dict(self.protocol_config, credentials=None, connid="%s:%d"%(host, port))
            if self.authenticator:
                try:
                    sock, credentials = self.authenticator(data_received)
                    config["credentials"]=credentials
                except AuthenticationError:
                    logging.info("failed to authenticate, rejecting data")
                    raise
            self.clients[cookie]=self.stream_class((host, port), self.transport_class, self.transport_kwargs)
            self.clients[cookie].buf_in.cookie=cookie
            self.clients[cookie].buf_out.cookie=cookie
            conn=Connection(self.service, Channel(self.clients[cookie]), config=config, _lazy=True)
            t = threading.Thread(target = self.handle_new_conn, args=(conn,))
            t.daemon=True
            t.start()
        resp=None
        with self.clients[cookie].upstream_lock:
            self.clients[cookie].upstream.write(decoded)
        #return self.void_stream.encode_data(self.clients[cookie].downstream.read(), cookie)
            resp=self.clients[cookie].downstream.read()
        if not resp: # No data to send, so we send the default page with no data
            resp=self.void_stream.encode_data("", cookie)
            
        return resp

    def handle_new_conn(self, conn):
        try:
            conn._init_service()
            conn.serve_all()
            #while True:
            #    conn.serve(0.01)
        except Exception as e:
            logging.error(e)
    
    def accept(self):
        """ Should call dispatch_data on data retrieved. Data must contain a \"cookie\" to define to which connection the packet of data belongs to """
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

    def start(self):
        """ blocking while the server is active """
        raise NotImplementedError()

class PupyAsyncTCPServer(PupyAsyncServer):
    def __init__(self, *args, **kwargs):
        super(PupyAsyncTCPServer, self).__init__(*args, **kwargs)
        self.sock=None
        self.hostname=kwargs['hostname']
        self.port=kwargs['port']

    def listen(self):
        s=None
        if not self.hostname:
            self.hostname=None
        last_exc=None
        for res in socket.getaddrinfo(self.hostname, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
            af, socktype, proto, canonname, sa = res
            try:
                s = socket.socket(af, socktype, proto)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except socket.error as msg:
                s = None
                last_exc=msg
                continue
            try:
                s.bind(sa)
                s.listen(100)
            except socket.error as msg:
                s.close()
                s = None
                last_exc=msg
                continue
            break
        self.sock=s
        if self.sock is None:
            raise last_exc

    def accept(self):
        try:
            s, addr = self.sock.accept()
            t=threading.Thread(target=self.serve_request, args=(s, addr,))
            t.daemon=True
            t.start()
            #TODO : make a pool of threads
        except Exception as e:
            logging.error(e)

    def serve_request(self, s, addr):
        full_req=b""
        s.settimeout(0.1)
        while True:
            try:
                d=s.recv(4096)
                if not d:
                    break
                full_req+=d
            except socket.timeout:
                break
        try:
            if full_req:
                response=self.dispatch_data(full_req, host=addr[0], port=addr[1])
                #print "sending response: %s"%repr(response)
                s.sendall(response)
        finally:
            s.close()

    def start(self):
        self.listen()
        self.active=True
        try:
            while self.active:
                self.accept()
        except EOFError:
            pass # server closed by another thread
        except KeyboardInterrupt:
            print("")
            print "keyboard interrupt!"
        finally:
            logging.info("server has terminated")
            self.close()

    def close(self):
        #TODO
        pass


class PupyTCPServer(ThreadPoolServer):
    def __init__(self, *args, **kwargs):
        if not "stream" in kwargs:
            raise ValueError("missing stream_class argument")
        if not "transport" in kwargs:
            raise ValueError("missing transport argument")
        self.stream_class=kwargs["stream"]
        self.transport_class=kwargs["transport"]
        self.transport_kwargs=kwargs["transport_kwargs"]
        del kwargs["stream"]
        del kwargs["transport"]
        del kwargs["transport_kwargs"]

        ThreadPoolServer.__init__(self, *args, **kwargs)

    def _authenticate_and_build_connection(self, sock):
        '''Authenticate a client and if it succeeds, wraps the socket in a connection object.
        Note that this code is cut and paste from the rpyc internals and may have to be
        changed if rpyc evolves'''
        # authenticate
        if self.authenticator:
            addrinfo = sock.getpeername()
            h=addrinfo[0]
            p=addrinfo[1]
            try:
                sock, credentials = self.authenticator(sock)
            except AuthenticationError:
                self.logger.info("%s:%s failed to authenticate, rejecting connection", h, p)
                return None
        else:
            credentials = None
        # build a connection
        addrinfo = sock.getpeername()
        h=addrinfo[0]
        p=addrinfo[1]
        config = dict(self.protocol_config, credentials=credentials, connid="%s:%d"%(h, p))
        return Connection(self.service, Channel(self.stream_class(sock, self.transport_class, self.transport_kwargs)), config=config)

