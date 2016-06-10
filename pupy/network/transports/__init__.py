# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
__all__=["Transport", "LAUNCHER_TYPE_ALL", "LAUNCHER_TYPE_BIND", "LAUNCHER_TYPE_CONNECT", "DEFAULT_RSA_PUB_KEY"]

class TransportException(Exception):
    pass

LAUNCHER_TYPE_ALL=0
LAUNCHER_TYPE_CONNECT=1
LAUNCHER_TYPE_BIND=2

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

class Transport(object):
    info="no description available"
    server=None
    client=None
    client_kwargs={}
    authenticator=None
    stream=None
    client_transport=None
    server_transport=None
    client_transport_kwargs={}
    server_transport_kwargs={}
    dependencies=[] # dependencies needed when generating payloads
    credentials=[] # list of credentials to embbed during payload generation
    name=None
    launcher_type=LAUNCHER_TYPE_ALL

    def __init__(self, bind_payload=False):
        super(Transport, self).__init__()
        if bind_payload:
            self.launcher_type=LAUNCHER_TYPE_BIND

    def parse_args(self, args):
        """ parse arguments and raise an error if there is missing/incorrect arguments """
        self.client_transport_kwargs.update(args)
        self.server_transport_kwargs.update(args)

