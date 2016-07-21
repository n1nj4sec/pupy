# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import os, os.path, tempfile, random, string
from network.transports import *
from network.lib import *
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
from rpyc.utils.authenticators import SSLAuthenticator

def ssl_authenticator():
    try:
        import pupy_credentials
        keystr=pupy_credentials.SSL_BIND_KEY
        certstr=pupy_credentials.SSL_BIND_CERT
    except:
        keystr=DEFAULT_SSL_BIND_KEY
        certstr=DEFAULT_SSL_BIND_CERT
    key_path=None
    cert_path=None
    if os.path.isfile("pupy.conf"):
        config = configparser.ConfigParser()
        config.read("pupy.conf")
        key_path=config.get("pupyd","keyfile").replace("\\",os.sep).replace("/",os.sep)
        cert_path=config.get("pupyd","certfile").replace("\\",os.sep).replace("/",os.sep)
    else:
        tmpdir=tempfile.gettempdir()
        cert_path=os.path.join(tmpdir, ''.join(random.choice(string.lowercase+string.digits) for _ in range(random.randint(5,8))))
        key_path=os.path.join(tmpdir,''.join(random.choice(string.lowercase+string.digits) for _ in range(random.randint(5,8))))
        with open(cert_path,'wb') as f:
            f.write(certstr.strip())
        with open(key_path,'wb') as f:
            f.write(keystr.strip())
    return SSLAuthenticator(key_path, cert_path, ciphers="SHA256+AES256:SHA1+AES256:@STRENGTH")

class TransportConf(Transport):
    info = "TCP transport wrapped with SSL"
    name = "ssl"
    server = PupyTCPServer
    client = PupySSLClient
    stream=PupySocketStream
    client_transport=DummyPupyTransport
    server_transport=DummyPupyTransport
    credentials = ["SSL_BIND_KEY", "SSL_BIND_CERT"]

    def authenticator(self):
        return ssl_authenticator()

