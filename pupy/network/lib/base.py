# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

class ReleaseChainedTransport(Exception):
    pass

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
            upstream_peer = kwargs.get('upstream_peer', ("127.0.0.1", 443))
            downstream_peer = kwargs.get('downstream_peer', ("127.0.0.1", 443))
            self.downstream=Buffer(transport_func=addGetPeer(downstream_peer))
            self.upstream=Buffer(transport_func=addGetPeer(upstream_peer))
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
            else:
                raise EOFError()
        except:
            raise EOFError()

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

        kwargs.update({
            'upstream_peer': self.upstream.transport.peer,
            'downstream_peer': self.downstream.transport.peer
        })

        self.chain = [
            klass(None, **kwargs) for klass in self.__class__._linearize()
        ]

        self._setup_callbacks()

    def _setup_callbacks(self):
        for idx, klass in enumerate(self.chain):
            klass.upstream.on_write = self._generate_write_callback(klass.upstream, idx, up=True)
            klass.downstream.on_write = self._generate_write_callback(klass.downstream, idx, up=False)

    @classmethod
    def _linearize(cls):
        for klass in cls.cls_chain:
            if issubclass(klass, TransportWrapper):
                for subklass in klass.cls_chain:
                    yield subklass
            else:
                yield klass

    def _generate_write_callback(self, buffer, idx, up=False):
        if up:
            return lambda: self.downstream_recv(buffer, idx+1)
        else:
            return lambda: self.upstream_recv(buffer, idx-1)

    def on_connect(self):
        for klass in self.chain:
            klass.on_connect()

    def on_close(self):
        for klass in self.chain:
            klass.on_close()

    def close(self):
        for klass in self.chain:
            try:
                klass.close()
            except Exception, e:
                pass

        super(TransportWrapper, self).close()

    def downstream_recv(self, data, idx=0):
        if idx > len(self.chain) - 1:
            if len(data):
                self.upstream.write(data.read())
        else:
            if len(data):
                try:
                    self.chain[idx].downstream_recv(data)
                except ReleaseChainedTransport:
                    self.chain = self.chain[:idx] + self.chain[idx+1:]
                    self._setup_callbacks()

    def upstream_recv(self, data, idx=None):
        if idx is None:
            idx = len(self.chain) - 1

        if idx < 0:
            if len(data):
                self.downstream.write(data.read())
        else:
            if len(data):
                self.chain[idx].upstream_recv(data)

def chain_transports(*args):
    """ chain 2 or more transports in such a way that the first argument is the transport seen at network level like t1(t2(t3(...(raw_data)...)))"""
    if len(args)<2:
        raise ValueError("chain_transports needs at least 2 transports !")
    class WrappedTransport(TransportWrapper):
        cls_chain=list(args)
    return WrappedTransport
