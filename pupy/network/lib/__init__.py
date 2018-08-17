import logging

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
except Exception, e:
    logger.exception('Transport rsa_aes disabled: %s', e)
    RSA_AESClient = None
    RSA_AESServer = None

try:
    from .transports.http import PupyHTTPClient, PupyHTTPServer
except Exception, e:
    logger.exception('Transport http disabled: %s', e)
    PupyHTTPClient = None
    PupyHTTPServer = None

try:
    from .transports.websocket import PupyWebSocketClient, PupyWebSocketServer
except Exception, e:
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

try:
    from .transports.scramblesuit.scramblesuit import ScrambleSuitClient, ScrambleSuitServer
except Exception as e:
    logger.exception('Transport scramblesuit disabled: %s', e)
    ScrambleSuitClient = None
    ScrambleSuitServer = None
