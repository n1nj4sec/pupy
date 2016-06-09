# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from network.transports import Transport
from network.lib import *
from network.lib.transports.obfs3.obfs3 import Obfs3Client, Obfs3Server

class TransportConf(Transport):
    info = "TCP transport using obfsproxy's obfs3 transport with a extra rsa+aes layer",
    name = "obfs3"
    server = PupyTCPServer
    client = PupyTCPClient
    stream = PupySocketStream
    client_transport = chain_transports(
            Obfs3Client,
            RSA_AESClient.custom(pubkey=DEFAULT_RSA_PUB_KEY, rsa_key_size=4096, aes_size=256),
        )
    server_transport = chain_transports(
            Obfs3Server,
            RSA_AESServer.custom(privkey_path="crypto/rsa_private_key.pem", rsa_key_size=4096, aes_size=256),
        )

