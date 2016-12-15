# -*- coding: UTF8 -*-
import netifaces
def get_local_ip(iface = None):
    '''
    Returns local ip address (no 127.0.0.1) or None
    '''
    try:
        if iface != None:
            ifaces = [iface]
        else:
            ifaces = netifaces.interfaces()
        for anInt in ifaces:
            addr = netifaces.ifaddresses(anInt)[netifaces.AF_INET][0]['addr']
            if addr != "127.0.0.1":
                return addr
        return None
    except Exception:
        return None
