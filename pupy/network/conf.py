#!/usr/bin/env python
# -*- coding: UTF8 -*-
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
config = configparser.ConfigParser()
try:
	config.read("pupy.conf")
except Exception:
	logging.error("couldn't read pupy.conf")

transports={
	"tcp_ssl" : {
		"server" : PupyTCPServer,
		"client": PupySSLClient,
		"client_kwargs" : {},
		"authenticator" : SSLAuthenticator(config.get("pupyd","keyfile").replace("\\",os.sep).replace("/",os.sep), config.get("pupyd","certfile").replace("\\",os.sep).replace("/",os.sep), ciphers="SHA256+AES256:SHA1+AES256:@STRENGTH"),
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
