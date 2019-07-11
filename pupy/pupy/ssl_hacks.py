# -*- coding: utf-8 -*-

__all__ = ('apply_ssl_hacks',)

import sys
import socket


def set_default_timeout(timeout=60):
    socket.setdefaulttimeout(timeout)


def change_default_verify_paths():
    if sys.platform == 'win32':
        return

    import ssl

    setattr(ssl, '_SSL_FILES', [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    ])

    setattr(ssl, '_SSL_PATHS', [
        "/etc/ssl/certs",
        "/system/etc/security/cacerts",
        "/usr/local/share/certs",
        "/etc/pki/tls/certs",
        "/etc/openssl/certs",
        "/etc/opt/csw/ssl/certs",
    ])

    def set_default_verify_paths(self):
        for path in ssl._SSL_PATHS:
            try:
                self.load_verify_locations(capath=path)
            except:
                pass

        for path in ssl._SSL_FILES:
            try:
                self.load_verify_locations(cafile=path)
            except:
                pass

        del path

    ssl.SSLContext.set_default_verify_paths = set_default_verify_paths


def apply_ssl_hacks():
    set_default_timeout()
    change_default_verify_paths()
