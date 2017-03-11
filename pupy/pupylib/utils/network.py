# -*- coding: utf-8 -*-
import netifaces
import urllib2
import netaddr

LOCAL_IP = None

def get_local_ip(iface=None, cache=True, external=False):
    '''
    Returns local ip address (no 127.0.0.1) or None
    '''

    global LOCAL_IP

    if LOCAL_IP and cache:
       return LOCAL_IP

    try:
        ifaces = []

        if iface:
            ifaces = [iface]

        elif external:
            proxy = urllib2.ProxyHandler()
            opener = urllib2.build_opener(proxy)
            opener.addheaders = [('User-agent', 'curl/7.50.0')]
            try:
                response = opener.open('http://ifconfig.co', timeout=5)
                if response.code == 200:
                    LOCAL_IP = str(netaddr.IPAddress(response.read()))
                    return LOCAL_IP
            except:
                pass

        if not ifaces:
            ifaces = [
                x for x in netifaces.interfaces() if not x.startswith(('lo', 'docker'))
            ]

        for anInt in ifaces:
            addresses = netifaces.ifaddresses(anInt)
            if not netifaces.AF_INET in addresses:
                continue

            ipaddr = addresses[netifaces.AF_INET][0]
            if not 'addr' in ipaddr:
                continue

            addr = ipaddr['addr']
            if addr not in ('127.0.0.1', '0.0.0.0'):
                return addr

    except Exception, e:
        print "exception: {}".format(e)
        return None
