# -*- coding: utf-8 -*-
import netifaces
import urllib2
import netaddr

def get_local_ip(iface = None):
    '''
    Returns local ip address (no 127.0.0.1) or None
    '''
    try:
        if iface != None:
            ifaces = [iface]
        else:
            proxy = urllib2.ProxyHandler()
            opener = urllib2.build_opener(proxy)
            opener.addheaders = [('User-agent', 'curl/7.50.0')]
            try:
                response = opener.open('http://ifconfig.co', timeout=5)
                if response.code == 200:
                    return str(netaddr.IPAddress(response.read()))
            except:
                pass

        for anInt in ifaces:
            addr = netifaces.ifaddresses(anInt)[netifaces.AF_INET][0]['addr']
            if addr != "127.0.0.1":
                return addr

        return None
    except Exception:
        return None
