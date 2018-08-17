# -*- coding: utf-8 -*-

__all__ = ['DummyPupyTransport']

from ..base import BasePupyTransport

class DummyPupyTransport(BasePupyTransport):
    __slots__ = ()

    def downstream_recv(self, data):
        """
        receiving obfuscated data from the remote client and writing deobfuscated data to downstream
        """
        data.write_to(self.upstream)

    def upstream_recv(self, data):
        """
        receiving clear-text data from local rpyc Stream and writing obfuscated data to upstream
        """
        data.write_to(self.downstream)
