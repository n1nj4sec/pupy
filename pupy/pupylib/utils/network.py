# -*- coding: utf-8 -*-
import netifaces
import urllib2
import logging
from netaddr import IPAddress

LISTENER_IP_EXTERNAL = None
LISTENER_IP_LOCAL = None

def ifconfig_co():
    proxy = urllib2.ProxyHandler()
    opener = urllib2.build_opener(proxy)
    opener.addheaders = [('User-agent', 'curl/7.50.0')]
    try:
        response = opener.open('http://ifconfig.co', timeout=5)
        if response.code == 200:
            return str(IPAddress(response.read().strip()))

    except Exception, e:
        logging.debug('ifconfig.co request failed: %s', e)


def get_listener_port(config, external=False):
    port = None
    if external:
        port = config.get('pupyd', 'external_port')

    if not port:
        port = config.get('pupyd', 'port')

    if not port:
        port = 443

    return int(port)


def get_listener_ip_with_local(cache=True, external=False, config=None, igd=None):
    '''
    Returns connectable external IP address
    '''

    global LISTENER_IP_EXTERNAL, LISTENER_IP_LOCAL

    if LISTENER_IP_LOCAL and cache and not external:
        return LISTENER_IP_LOCAL, True

    if LISTENER_IP_EXTERNAL and cache and external:
        return LISTENER_IP_EXTERNAL, False

    if not LISTENER_IP_EXTERNAL and config:
        LISTENER_IP_EXTERNAL = config.getip('pupyd', 'external')

        if not LISTENER_IP_EXTERNAL and config.getboolean(
            'pupyd', 'allow_requests_to_external_services'
        ):
            LISTENER_IP_EXTERNAL = ifconfig_co()

            if not LISTENER_IP_EXTERNAL and igd and igd.available:
                try:
                    LISTENER_IP_EXTERNAL = str(IPAddress(
                        igd.GetExternalIP()['NewExternalIPAddress']))
                except Exception, e:
                    logging.debug('IGD Exception: %s', e)

    if not LISTENER_IP_LOCAL and config:
        LISTENER_IP_LOCAL = config.getip('pupyd', 'address')

    ifaces = []

    if not LISTENER_IP_LOCAL:
        try:
            ifaces = [
                x for x in netifaces.interfaces() if not x.startswith(
                    ('lo', 'docker')
                )
            ]

            for anInt in ifaces:
                addresses = netifaces.ifaddresses(anInt)
                if netifaces.AF_INET not in addresses:
                    continue

                ipaddr = addresses[netifaces.AF_INET][0]
                if 'addr' not in ipaddr:
                    continue

                addr = ipaddr['addr']
                if addr not in ('127.0.0.1', '0.0.0.0'):
                    LISTENER_IP_LOCAL = addr
                    break

        except Exception, e:
            logging.debug('Exception during interfaces enumeration: %s', e)
            return None

    if not external and LISTENER_IP_LOCAL:
        return LISTENER_IP_LOCAL, True

    if external and LISTENER_IP_EXTERNAL:
        return LISTENER_IP_EXTERNAL, False

    if LISTENER_IP_EXTERNAL:
        return LISTENER_IP_EXTERNAL, False

    if LISTENER_IP_LOCAL:
        return LISTENER_IP_LOCAL, True

def get_listener_ip(cache=True, external=False, config=None, igd=None):
    return get_listener_ip_with_local(cache, external, config, igd)[0]
