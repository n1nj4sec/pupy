import logging

from .streams import *
from .base import chain_transports
from .servers import PupyTCPServer, PupyUDPServer
from .clients import PupyTCPClient, PupySSLClient, PupyProxifiedTCPClient, PupyProxifiedSSLClient, PupyAsyncClient, PupyUDPClient
from .transports.dummy import DummyPupyTransport
from .transports.dummy_packets import DummyPupyPacketsTransport
from .transports.b64 import B64Client, B64Server, B64Transport
from .transports.http import PupyHTTPClient, PupyHTTPServer
from .transports.websocket import PupyWebSocketClient, PupyWebSocketServer
from .transports.xor import XOR
from .transports.aes import AES256, AES128
from .transports.rsa_aes import RSA_AESClient, RSA_AESServer

try:
    from .transports.ec4 import EC4TransportServer, EC4TransportClient
except Exception as e:
    logging.exception('Transport ec4 disabled: {}'.format(e))
    EC4TransportServer=None
    EC4TransportClient=None

try:
    from .transports.scramblesuit.scramblesuit import ScrambleSuitClient, ScrambleSuitServer
except Exception as e:
    logging.exception('Transport scramblesuit disabled: {}'.format(e))
    ScrambleSuitClient=None
    ScrambleSuitServer=None
