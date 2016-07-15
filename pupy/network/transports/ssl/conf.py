# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import os
from network.transports import Transport
from network.lib import *
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
from rpyc.utils.authenticators import SSLAuthenticator
import logging

class TransportConf(Transport):
    info = "TCP transport wrapped with SSL"
    name = "ssl"
    server = PupyTCPServer
    client = PupySSLClient
    stream=PupySocketStream
    client_transport=DummyPupyTransport
    server_transport=DummyPupyTransport

    def authenticator(self):
        if not os.path.isfile("pupy.conf"): 
            logging.warning("Impossible to read the file pupy.conf in authenticator")
            return SSLAuthenticator("bindserver.pem", "bindcert.pem", ciphers="SHA256+AES256:SHA1+AES256:@STRENGTH")
        else:
            config = configparser.ConfigParser()
            config.read("pupy.conf")
            return SSLAuthenticator(config.get("pupyd","keyfile").replace("\\",os.sep).replace("/",os.sep), config.get("pupyd","certfile").replace("\\",os.sep).replace("/",os.sep), ciphers="SHA256+AES256:SHA1+AES256:@STRENGTH")

