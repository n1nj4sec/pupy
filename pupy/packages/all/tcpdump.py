# -*- coding: UTF8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from scapy.all import *


class SniffSession(object):
    def __init__(self, sniff_callback, iface=None, bpf=None, timeout=None, count=0, save_pcap=None):
        self.stopped=True
        self.sniff_callback=sniff_callback
        self.iface=iface
        self.bpf=bpf
        self.timeout=timeout
        self.count=count
        self.save_pcap=save_pcap

    def __del__(self):
        self.stopped=True

    def start(self):
        self.stopped=False
        try:
            sniff(prn=self.sniff_callback, filter=self.bpf, count=self.count, timeout=self.timeout, store=0, iface=self.iface)
        except Exception:
            print "sniff stopped" #debug
            self.stopped=True
            raise

    def stop(self):
        self.stopped=True

    def is_stopped(self, x):
        return self.stopped

if __name__=="__main__":
    import time
    def cb(pkt):
        print pkt.summary()
    t=SniffSession(cb, iface="eth0")
    t.start()
    t.stop()



