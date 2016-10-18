# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from scapy.all import *

def format_response(pkt):
    res=""
    if "R" in pkt.sprintf("%TCP.flags%"):
        res+="TCP/{:<7}  closed    {}".format(pkt[TCP].sport, pkt.sprintf("{TCP:%TCP.flags%}{ICMP:%IP.src% - %ICMP.type%}"))
    elif pkt.sprintf("%TCP.flags%")=="SA":
        res+="TCP/{:<7}  open      {}".format(pkt[TCP].sport, pkt.sprintf("{TCP:%TCP.flags%}{ICMP:%IP.src% - %ICMP.type%}"))
    else:
        res+="TCP/{:<7}  filtered  {}".format(pkt[TCP].sport, pkt.sprintf("{TCP:%TCP.flags%}{ICMP:%IP.src% - %ICMP.type%}"))
    return res+"\n"

class PortScanner(object):
    def __init__(self):
        pass
    def scan(self, address, ports, timeout=4, iface=None):
        res=""
        '''
        ans,unans=sr(IP(dst=address)/TCP(flags="S",dport=list(ports)), verbose=False, iface=iface, timeout=timeout)
        for req,resp in ans:
            res+=format_response(resp)
        return res
        '''
                
