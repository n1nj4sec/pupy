# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

class Circuit(object):
    """ alias for obfsproxy style syntax"""
    def __init__(self, stream, transport, downstream=None, upstream=None):
        if stream is None:
            self.downstream=downstream
            self.upstream=upstream
            self.stream=None
        else:
            self.downstream=stream.downstream
            self.upstream=stream.upstream
            self.stream=stream
        self.transport=transport
    def close(self):
        self.transport.on_close()
        self.stream.close()

class BasePupyTransport(object):
    def __init__(self, stream, **kwargs):
        if stream is None:
            self.downstream=Buffer(transport_func=addGetPeer(("127.0.0.1", 443)))
            self.upstream=Buffer(transport_func=addGetPeer(("127.0.0.1", 443)))
            self.stream = None
        else:
            self.downstream=stream.downstream
            self.upstream=stream.upstream
            self.stream=stream
        self.circuit=Circuit(self.stream, self, downstream=self.downstream, upstream=self.upstream)
        self.cookie=None

    def on_connect(self):
        """
            We just established a connection. Handshake time ! :-)
        """
        if hasattr(self, 'circuitConnected'):
            """ obfsproxy style alias """
            return self.circuitConnected()

    def on_close(self):
        """
            called when the connection has been closed
        """
        if hasattr(self, 'circuitDestroyed'):
            """ obfsproxy style alias """
            return self.circuitDestroyed()

    def downstream_recv(self, data):
        """
            receiving obfuscated data from the remote client and writing deobfuscated data to downstream
        """
        if hasattr(self, 'receivedDownstream'):
            """ obfsproxy style alias """
            return self.receivedDownstream(data)
        raise NotImplementedError()

    def upstream_recv(self, data):
        """
            receiving clear-text data from local rpyc Stream and writing obfuscated data to upstream
        """
        if hasattr(self, 'receivedUpstream'):
            return self.receivedUpstream(data)
            """ obfsproxy style alias """
        raise NotImplementedError()

class BaseTransport(BasePupyTransport):
    """ obfsproxy style alias """
    pass

class PluggableTransportError(Exception):
    pass

from buffer import Buffer
from streams.PupySocketStream import addGetPeer

class TransportWrapper(BasePupyTransport):
    cls_chain=[]
    def __init__(self, stream, **kwargs):
        super(TransportWrapper, self).__init__(stream, **kwargs)
        self.insts=[]
        for c in self.cls_chain:
            self.insts.append(c(None, **kwargs))

        #upstream chaining :
        self.insts[-1].upstream=self.upstream
        self.insts[-1].circuit.upstream=self.upstream

        #downstream chaining :
        self.insts[0].downstream=self.downstream
        self.insts[0].circuit.downstream=self.downstream
        #overloading len of buffer with the max of all chained buff
        #self.upstream.overload_len = (lambda s:max([len(x.upstream.buffer) for x in self.insts]))
        #self.downstream.overload_len = (lambda s:max([len(x.downstream.buffer) for x in self.insts]))

    def on_connect(self):
        for ins in self.insts:
            ins.on_connect()

    def on_close(self):
        for ins in self.insts:
            ins.on_close()

    def downstream_recv(self, data):
        self.insts[0].downstream_recv(data)
        for i,ins in enumerate(self.insts[1:]):
            ins.downstream_recv(self.insts[i].upstream)
            self.cookie=ins.cookie
        
    def upstream_recv(self, data):
        self.insts[-1].upstream_recv(data)
        i=len(self.insts)-2
        while i>=0:
            self.insts[i].upstream_recv(self.insts[i+1].downstream)
            i-=1

def chain_transports(*args):
    """ chain 2 or more transports in such a way that the first argument is the transport seen at network level like t1(t2(t3(...(raw_data)...)))"""
    if len(args)<2:
        raise ValueError("chain_transports needs at least 2 transports !")
    class WrappedTransport(TransportWrapper):
        cls_chain=list(args)
    return WrappedTransport

