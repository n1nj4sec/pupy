# -*- coding: utf-8 -*-
import netifaces
import urllib2
import netaddr
import logging

LISTENER_IP = None

def ifconfig_co():
    proxy = urllib2.ProxyHandler()
    opener = urllib2.build_opener(proxy)
    opener.addheaders = [('User-agent', 'curl/7.50.0')]
    try:
        response = opener.open('http://ifconfig.co', timeout=5)
        if response.code == 200:
            return netaddr.IPAddress(response.read())

    except Exception, e:
        logging.debug('ifconfig.co request failed: {}'.format(e))


def get_listener_port(config, external=False):
    port = None
    if external:
        port = config.get('pupyd', 'external_port')

    if not port:
        port = config.get('pupyd', 'port')

    if not port:
        port = 443

    return int(port)


def get_listener_ip(cache=True, external=False, config=None, igd=None):
    '''
    Returns connectable external IP address
    '''

    global LISTENER_IP

    if config and external:
        LISTENER_IP = config.getip('pupyd', 'external')

        if not LISTENER_IP and config.getboolean(
            'pupyd', 'allow_requests_to_external_services'
        ):

            if LISTENER_IP and cache:
                return LISTENER_IP

            LISTENER_IP = ifconfig_co()

            if not LISTENER_IP and igd and igd.available:
                try:
                    LISTENER_IP = netaddr.IPAddress(
                        igd.GetExternalIP()['NewExternalIPAddress']
                    )
                except:
                    pass

    elif config and not external:
        LISTENER_IP = config.getip('pupyd', 'address')

    ifaces = []

    if not LISTENER_IP:
        try:

            ifaces = [
                x for x in netifaces.interfaces() if not x.startswith(
                    ('lo', 'docker')
                )
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
                    LISTENER_IP = addr
                    break

        except Exception, e:
            logging.debug('Exception during interfaces enumeration: {}'.format(e))
            return None

    return LISTENER_IP
