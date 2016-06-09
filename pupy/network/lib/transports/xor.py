# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

""" This module contains an implementation of a simple xor transport for pupy. """

from ..base import BasePupyTransport, TransportError
import logging
import traceback

STREAM=1
BLOCK=2


class XORTransport(BasePupyTransport):
    """
    Implements a transport that simply apply a XOR to each byte
    """
    xorkey=None
    channel_type=STREAM # STREAM or BLOCK

    def __init__(self, *args, **kwargs):
        super(XORTransport, self).__init__(*args, **kwargs)
        if "xorkey" in kwargs:
            self.xorkey=kwargs["xorkey"]
        if self.xorkey is None:
            raise TransportError("A xorkey needs to be supplied")
        self.xor_index_up=0
        self.xor_index_down=0

    def upstream_recv(self, data):
        try:
            if self.channel_type == BLOCK:
                self.downstream.write(''.join((chr(ord(x)^ord(y)) for x,y in zip(self.xorkey,data.read()))))
            elif self.channel_type == STREAM:
                xored_buf=b""
                for x in data.read():
                    xored_buf+=chr(ord(x)^ord(self.xorkey[self.xor_index_up]))
                    self.xor_index_up+=1
                    if self.xor_index_up >= len(self.xorkey):
                        self.xor_index_up=0
                self.downstream.write(xored_buf)
            else:
                raise TransportError("No such channel type %s"%self.channel_type)
        except Exception as e:
            logging.debug(e)

    def downstream_recv(self, data):
        try:
            if self.channel_type == BLOCK:
                self.upstream.write(''.join((chr(ord(x)^ord(y)) for x,y in zip(self.xorkey,data.read()))))
            elif self.channel_type == STREAM:
                xored_buf=b""
                for x in data.read():
                    xored_buf+=chr(ord(x)^ord(self.xorkey[self.xor_index_down]))
                    self.xor_index_down+=1
                    if self.xor_index_down >= len(self.xorkey):
                        self.xor_index_down=0
                self.upstream.write(xored_buf)
            else:
                raise TransportError("No such channel type %s"%self.channel_type)
        except Exception as e:
            logging.debug(e)

class XORClient(XORTransport):
    pass

class XORServer(XORTransport):
    pass

class XOR(XORTransport): #alias
    pass

