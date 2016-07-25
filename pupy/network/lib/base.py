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
        self.closed=False

    @classmethod
    def customize(cls, **kwargs):
        """ return a class with some existing attributes customized """
        for name, value in kwargs.iteritems():
            if name in ["cookie", "circuit", "upstream", "downstream", "stream"]:
                raise TransportError("you cannot customize the protected attribute %s"%name)
            if not hasattr(cls, name):
                raise TransportError("Transport has no attribute %s"%name)
        NewSubClass = type('CustomizedTransport', (cls,), kwargs)
        return NewSubClass

    @classmethod
    def custom(cls, **kwargs):
        return cls.customize(**kwargs)

    @classmethod
    def set(cls, **kwargs):
        return cls.customize(**kwargs)

    def close(self):
        self.closed=True
        try:
            self.on_close()
        except:
            pass
        try:
            if self.stream:
                self.stream.close()
        except:
            pass
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

class TransportError(Exception):
    pass

class PluggableTransportError(Exception):
    pass

from buffer import Buffer
from streams.PupySocketStream import addGetPeer
import logging

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

