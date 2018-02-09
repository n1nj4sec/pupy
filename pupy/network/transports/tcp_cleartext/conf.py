# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from network.lib import PupyTCPServer, PupyTCPClient, PupySocketStream
from network.lib import DummyPupyTransport
from network.transports import Transport

class TransportConf(Transport):
    info = "Simple TCP transport transmitting in cleartext"
    name="tcp_cleartext"
    server=PupyTCPServer
    client=PupyTCPClient
    stream=PupySocketStream
    client_transport=DummyPupyTransport
    server_transport=DummyPupyTransport
