# -*- coding: utf-8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import sys
import scapy.all

from threading import Thread

from scapy.all import *
from rpyc import async
from psutil import net_if_addrs

class StopSniff(Exception):
    pass

class SniffSession(Thread):
    def __init__(self, on_data, on_close, iface=None, bpf=None, timeout=None, count=0):
        super(SniffSession, self).__init__()
        self.daemon = True

        self.stopped = True

        self._on_data = on_data
        self._on_close = on_close

        self.bpf = bpf
        self.timeout = timeout
        self.count = count
        self.iface = None
        self.name = None
        self._set_iface(iface)

    def _set_iface(self, iface):
        nice_name = iface

        if hasattr(scapy.all, 'IFACES'):
            if not type(iface) == unicode:
                iface = iface.decode('utf-8')
                nice_name = iface

            iface = iface.encode(sys.getfilesystemencoding())

            known_ifaces = net_if_addrs()
            if not iface in known_ifaces:
                raise ValueError('Unknown interface {} / {}')

            mac = None
            for family in known_ifaces[iface]:
                if '-' in family.address:
                    mac = family.address
                    break

            if not mac:
                raise ValueError('Could not find MAC for specified interface')

            for guid, scapy_iface in IFACES.items():
                if scapy_iface.mac.replace('-', ':') == mac.replace('-', ':'):
                    self.iface = scapy_iface
                    break

            if not self.iface:
                raise ValueError('Could not find scapy interface')

        else:
            self.iface = iface

        self.nice_name = nice_name

    def sniff_callback(self, packet):
        if self.stopped:
            raise StopSniff()

        if self._on_data:
            self._on_data(str(packet))

    def run(self):
        self.stopped = False
        reason = None

        try:
            sniff(
                prn=self.sniff_callback,
                filter=self.bpf,
                count=self.count,
                timeout=self.timeout,
                store=0,
                iface=self.iface
            )

        except StopSniff:
            reason = 'Interrupted'

        except Exception, e:
            reason = str(e)

        finally:
            self.stopped = True
            if self._on_close:
                try:
                    self._on_close(reason)
                except:
                    pass


    def stop(self):
        self.stopped = True

    def is_stopped(self, x):
        return self.stopped

def run(on_data, on_close, iface=None, bpf=None, timeout=None, count=0):
    sniffer = SniffSession(
        async(on_data), async(on_close), iface, bpf, timeout, count)

    sniffer.start()

    return sniffer.nice_name, sniffer.stop

if __name__=="__main__":
    import time
    def cb(pkt):
        print pkt.summary()
    t=SniffSession(cb, iface="eth0")
    t.start()
    t.stop()
