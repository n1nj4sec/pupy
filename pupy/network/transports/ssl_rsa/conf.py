# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import os
from network.transports import *
from network.lib import *
from network.transports.ssl.conf import ssl_authenticator

# This doesn't make any sence, but who cares?

class TransportConf(Transport):
    info = "TCP transport wrapped with SSL with an additional pupy's rsa layer"
    name = "ssl_rsa"
    server = PupyTCPServer
    client = PupySSLClient
    stream=PupySocketStream
    credentials = [
        'SIMPLE_RSA_PUB_KEY', 'SIMPLE_RSA_PRIV_KEY',
        'SSL_CA_CERT',
        'SSL_BIND_KEY', 'SSL_BIND_CERT',
        'SSL_CLIENT_KEY', 'SSL_CLIENT_CERT'
    ]

    def authenticator(self):
        return ssl_authenticator()

    def __init__(self, *args, **kwargs):
        Transport.__init__(self, *args, **kwargs)
        try:
            import pupy_credentials
            RSA_PUB_KEY = pupy_credentials.SIMPLE_RSA_PUB_KEY
            RSA_PRIV_KEY = pupy_credentials.SIMPLE_RSA_PRIV_KEY

        except:
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
