# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of
# the project for the detailed licence terms

import os, tempfile, random, string, logging
from os import path, unlink
from network.transports import *
from network.lib import *

import sys

from rpyc.utils.authenticators import AuthenticationError
from rpyc.lib import safe_import

ssl = safe_import("ssl")

class PupySSLAuthenticator(object):
    def __init__(self, keystr, certstr):
        self.keystr = keystr.strip()
        self.certstr = certstr.strip()
        self.ciphers = 'SHA256+AES256:SHA1+AES256:@STRENGTH'
        self.cert_reqs = ssl.CERT_NONE
        self.ssl_version = ssl.PROTOCOL_TLSv1

    def __call__(self, sock):
        wrapped_socket = None
        tmp_cert_path = None
        tmp_key_path = None

        try:
            fd_cert_path, tmp_cert_path = tempfile.mkstemp()
            fd_key_path, tmp_key_path = tempfile.mkstemp()

            os.write(fd_cert_path, self.certstr)
            os.close(fd_cert_path)
            os.write(fd_key_path, self.keystr)
            os.close(fd_key_path)

            try:
                wrapped_socket = ssl.wrap_socket(
                    sock,
                    keyfile=tmp_key_path,
                    certfile=tmp_cert_path,
                    server_side=True,
                    ca_certs=None,
                    cert_reqs=self.cert_reqs,
                    ssl_version = self.ssl_version
                )
            except ssl.SSLError:
                ex = sys.exc_info()[1]
                raise AuthenticationError(str(ex))

            return wrapped_socket, wrapped_socket.getpeercert()

        finally:
            if path.exists(tmp_cert_path):
                unlink(tmp_cert_path)

            if path.exists(tmp_key_path):
                unlink(tmp_key_path)


def ssl_authenticator():
    keystr = b''
    certstr = b''

    try:
        import pupy_credentials
        keystr = pupy_credentials.SSL_BIND_KEY
        certstr = pupy_credentials.SSL_BIND_CERT

    except:
        from pupylib.PupyConfig import PupyConfig
        from pupylib.PupyCredentials import Credentials

        config = PupyConfig()
        credentials = Credentials()

        key_path = config.get('pupyd', 'keyfile')
        cert_path = config.get('pupyd', 'certfile')

        if path.exists(key_path):
            with open(key_path) as key:
                keystr = key.read()
        else:
            logging.error('SSL Key {} not found'.format(key_path))
            keystr = credentials['SSL_BIND_KEY']

        if path.exists(cert_path):
            with open(cert_path) as cert:
                certstr = cert.read()
        else:
            logging.error('SSL Certificate {} not found'.format(cert_path))

    return PupySSLAuthenticator(keystr, certstr)


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
