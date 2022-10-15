# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import netifaces
import logging

from netaddr import IPAddress, AddrFormatError
from network.lib.online import external_ip

LISTENER_IP_EXTERNAL = None
LISTENER_IP_LOCAL = None


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
        try:
            LISTENER_IP_EXTERNAL = config.getip('pupyd', 'external')
        except AddrFormatError:
            LISTENER_IP_EXTERNAL = None

        if not LISTENER_IP_EXTERNAL and config.getboolean(
            'pupyd', 'allow_requests_to_external_services'
        ):
            if igd and igd.available:
                try:
                    LISTENER_IP_EXTERNAL = str(IPAddress(
                        igd.GetExternalIP()['NewExternalIPAddress']))
                except Exception as e:
                    logging.warning('IGD Exception: %s', e)

            if not LISTENER_IP_EXTERNAL:
                ipv6 = config.getboolean('pupyd', 'ipv6')

                LISTENER_IP_EXTERNAL = external_ip(force_ipv4=not ipv6)

        if not LISTENER_IP_EXTERNAL and igd and igd.available:
            logging.warning('Failed to find out external IP')

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

        except Exception as e:
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
