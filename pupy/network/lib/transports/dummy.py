# -*- coding: utf-8 -*-
from ..base import BasePupyTransport

class DummyPupyTransport(BasePupyTransport):
    def downstream_recv(self, data):
        """
        receiving obfuscated data from the remote client and writing deobfuscated data to downstream
        """
        d = data.read()
        print "RECV: ", len(d)
        self.upstream.write(d)

    def upstream_recv(self, data):
        """
        receiving clear-text data from local rpyc Stream and writing obfuscated data to upstream
        """
        d = data.read()
        print "SEND: ", len(d)
        self.downstream.write(d)
