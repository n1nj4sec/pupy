# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from network.transports import Transport
from network.lib import *

class TransportConf(Transport):
    info = "Simple UDP transport transmitting in cleartext"
    name="udp_cleartext"
    server=PupyUDPServer
    client=PupyUDPClient
    stream=PupyUDPSocketStream
    client_transport=DummyPupyTransport
    server_transport=DummyPupyTransport

