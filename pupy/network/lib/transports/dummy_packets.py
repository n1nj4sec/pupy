# -*- coding: utf-8-*-
from ..base import BasePupyTransport

import struct

class DummyPupyPacketsTransport(BasePupyTransport):
    def __init__(self, *args, **kwargs):
        if 'mtu' in kwargs:
            self.mtu = kwargs['mtu']
            del kwargs['mtu']
        else:
            self.mtu = 1450

        self.to_read = 0
        self.packets = b''

        BasePupyTransport.__init__(self, *args, **kwargs)

    def downstream_recv(self, data):
        """
        Read data by portions
        """
        upcoming = data.read()
        packets = self.packets + upcoming

        while True:
            if self.to_read == 0:
                self.to_read = struct.unpack_from('>I', packets)[0]
                packets = packets[4:]

            if self.to_read <= len(packets):
                self.upstream.write(packets[:self.to_read])
                packets = packets[self.to_read:]
                self.to_read = 0

                if self.to_read == 0 and len(packets) > 0:
                    continue

            break

        self.packets = packets


    def upstream_recv(self, data):
        """
        Write data by portions
        """

        packets = data.read()

        packets = struct.pack('>I', len(packets)) + packets

        for part in [packets[i:i+self.mtu] for i in xrange(0, len(packets), self.mtu)]:
            self.downstream.write(part)
