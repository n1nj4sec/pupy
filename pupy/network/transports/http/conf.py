# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from network.transports import Transport, LAUNCHER_TYPE_BIND
from network.lib import PupyTCPServer, PupyTCPClient, PupySocketStream
from network.lib import PupyHTTPClient, RSA_AESClient
from network.lib import PupyHTTPServer, RSA_AESServer
from network.lib import chain_transports

class TransportConf(Transport):
    info = "TCP transport using HTTP with RSA+AES"
    name = "http"
    server = PupyTCPServer
    client = PupyTCPClient
    stream = PupySocketStream
    credentials = ['SIMPLE_RSA_PRIV_KEY', 'SIMPLE_RSA_PUB_KEY']
    internal_proxy_impl = ['HTTP']

    def __init__(self, *args, **kwargs):
        Transport.__init__(self, *args, **kwargs)

        self.client_transport_kwargs.update({
            'host': None
        })

        try:
            import pupy_credentials
            RSA_PUB_KEY = pupy_credentials.SIMPLE_RSA_PUB_KEY
            RSA_PRIV_KEY = pupy_credentials.SIMPLE_RSA_PRIV_KEY

        except ImportError:
            from pupylib.PupyCredentials import Credentials
            credentials = Credentials()
            RSA_PUB_KEY = credentials['SIMPLE_RSA_PUB_KEY']
            RSA_PRIV_KEY = credentials['SIMPLE_RSA_PRIV_KEY']

        user_agent = 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) '\
          'Chrome/41.0.2228.0 Safari/537.36'

        if self.launcher_type == LAUNCHER_TYPE_BIND:
            self.client_transport = chain_transports(
                    PupyHTTPClient.custom(keep_alive=True, user_agent=user_agent),
                    RSA_AESServer.custom(privkey=RSA_PRIV_KEY, rsa_key_size=4096, aes_size=256),
                )
            self.server_transport = chain_transports(
                    PupyHTTPServer.custom(verify_user_agent=user_agent),
                    RSA_AESClient.custom(pubkey=RSA_PUB_KEY, rsa_key_size=4096, aes_size=256),
                )

        else:
            self.client_transport = chain_transports(
                    PupyHTTPClient.custom(keep_alive=True, user_agent=user_agent),
                    RSA_AESClient.custom(pubkey=RSA_PUB_KEY, rsa_key_size=4096, aes_size=256),
                )
            self.server_transport = chain_transports(
                    PupyHTTPServer.custom(verify_user_agent=user_agent),
                    RSA_AESServer.custom(privkey=RSA_PRIV_KEY, rsa_key_size=4096, aes_size=256),
                )
