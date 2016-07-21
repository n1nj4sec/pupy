# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import os
from network.transports import *
from network.lib import *
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
from network.transports.ssl.conf import ssl_authenticator

class TransportConf(Transport):
    info = "TCP transport wrapped with SSL with an additional pupy's rsa layer"
    name = "ssl_rsa"
    server = PupyTCPServer
    client = PupySSLClient
    stream=PupySocketStream
    credentials = ["RSA_PUB_KEY", "SSL_BIND_KEY", "SSL_BIND_CERT"]

    def authenticator(self):
        return ssl_authenticator()
    def __init__(self, *args, **kwargs):
        Transport.__init__(self, *args, **kwargs)
        try:
            import pupy_credentials
            rsa_pub_key=pupy_credentials.RSA_PUB_KEY
        except:
            rsa_pub_key=DEFAULT_RSA_PUB_KEY

        if self.launcher_type == LAUNCHER_TYPE_BIND: #reversing the RSA client/server for BIND payloads so the private key doesn't go on the target
            self.client_transport = RSA_AESServer.custom(privkey_path="crypto/rsa_private_key.pem", rsa_key_size=4096, aes_size=256)
            self.server_transport = RSA_AESClient.custom(pubkey=rsa_pub_key, rsa_key_size=4096, aes_size=256)
        else:
            self.client_transport = RSA_AESClient.custom(pubkey=rsa_pub_key, rsa_key_size=4096, aes_size=256)
            self.server_transport = RSA_AESServer.custom(privkey_path="crypto/rsa_private_key.pem", rsa_key_size=4096, aes_size=256)

