# -*- coding: utf-8-*-

if __name__ == '__main__':
    import sys
    sys.path.append('..')

from os import path, urandom, chmod, makedirs

import logging
import string
import errno
import time

from network.transports import *
from network.lib.picocmd.ecpv import ECPV

from M2Crypto import X509, EVP, RSA, ASN1, BIO
import rsa

DEFAULT_ROLE='CLIENT'

class Credentials(object):
    USER_CONFIG = path.expanduser(
        path.join('~', '.config', 'pupy', 'credentials.py')
    )

    CONFIG_FILES = [
        path.join(path.dirname(__file__), '..', 'crypto', 'credentials.py'),
        path.join('crypto', 'credentials.py'),
        USER_CONFIG,
    ]

    def __init__(self, role=None):
        self._generate()

        role = role or DEFAULT_ROLE
        self.role = role.upper() if role else 'ANY'

        if not self.role in ('CONTROL', 'CLIENT'):
            raise ValueError('Unsupported role: {}'.format(self.role))

        self._credentials = {}
        for config in self.CONFIG_FILES:
            if path.exists(config):
                with open(config) as creds:
                    exec creds.read() in self._credentials

    def __getitem__(self, key):
        env = globals()

        if key in self._credentials:
            return self._credentials[key]
        elif '{}_{}'.format(self.role, key) in self._credentials:
            return self._credentials['{}_{}'.format(self.role, key)]
        elif key in env:
            return env[key]
        elif 'DEFAULT_{}'.format(key) in env:
            logging.warning("Using default credentials for {}".format(key))
            return env['DEFAULT_{}'.format(key)]
        else:
            return None

    def __setitem__(self, key, value):
        self._credentials[key] = value

    def __iter__(self):
        return iter(self._credentials)

    def _generate_password(self, length):
        alphabet = string.punctuation + string.ascii_letters + string.digits
        return ''.join(
            alphabet[ord(c) % len(alphabet)] for c in urandom(length)
        )

    def _generate_id(self, length):
        alphabet = string.ascii_letters
        return ''.join(
            alphabet[ord(c) % len(alphabet)] for c in urandom(length)
        )

    def _generate_scramblesuit_passwd(self):
        return self._generate_password(20)

    def _generate_bind_payloads_password(self):
        return self._generate_password(20)

    def _generate_ecpv_keypair(self, curve='brainpoolP160r1'):
        return ECPV(curve=curve).generate_key()

    def _generate_rsa_keypair(self, bits=1024):
        key = RSA.gen_key(bits, 65537)
        private_key = key.as_pem(cipher=None)
        rsa_privkey = rsa.key.PrivateKey.load_pkcs1(
            private_key, 'PEM'
        )
        rsa_pubkey = rsa.key.PublicKey(rsa_privkey.n, rsa_privkey.e)
        public_key = rsa_pubkey.save_pkcs1('PEM')

        return private_key, public_key, key

    def _generate_ssl_ca(self):
        ca_key_pem, ca_cert_pem, ca_key = self._generate_rsa_keypair()

        t = long(time.time())
        now = ASN1.ASN1_UTCTIME()
        now.set_time(t)
        expire = ASN1.ASN1_UTCTIME()
        expire.set_time(t + 365 * 24 * 60 * 60)

        pk = EVP.PKey()
        pk.assign_rsa(ca_key)

        cert = X509.X509()
        cert.get_subject().O = self._generate_id(10)
        cert.set_serial_number(1)
        cert.set_version(3)
        cert.set_not_before(now)
        cert.set_not_after(expire)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(pk)
        cert.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE'))
        cert.add_ext(X509.new_extension('subjectKeyIdentifier', cert.get_fingerprint()))
        cert.sign(pk, 'sha1')

        return pk.as_pem(cipher=None), cert.as_pem(), pk, cert

    def _generate_ssl_keypair(self, rsa_key, ca_key, ca_cert, role='CONTROL', client=False, serial=2):

        t = long(time.time())
        now = ASN1.ASN1_UTCTIME()
        now.set_time(t)
        expire = ASN1.ASN1_UTCTIME()
        expire.set_time(t + 365 * 24 * 60 * 60)

        pk = EVP.PKey()
        pk.assign_rsa(rsa_key)

        cert = X509.X509()
        cert.get_subject().O = self._generate_id(10)
        cert.get_subject().OU = role
        cert.set_serial_number(serial)
        cert.set_version(3)
        cert.set_not_before(now)
        cert.set_not_after(expire)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(pk)
        cert.add_ext(X509.new_extension('basicConstraints', 'critical,CA:FALSE'))
        cert.add_ext(X509.new_extension('subjectKeyIdentifier', cert.get_fingerprint()))
        if client:
            cert.add_ext(X509.new_extension('keyUsage', 'critical,digitalSignature'))
            cert.add_ext(X509.new_extension('nsCertType', 'client'))
        else:
            cert.add_ext(X509.new_extension('keyUsage', 'critical,keyEncipherment'))
            cert.add_ext(X509.new_extension('nsCertType', 'server'))
        cert.sign(ca_key, 'sha1')

        return pk.as_pem(cipher=None), cert.as_pem()

    def _generate(self, force=False):
        if path.exists(self.USER_CONFIG) and not force:
            return

        logging.warning("Generating credentials to {}".format(self.USER_CONFIG))

        ECPV_PRIVATE_KEY, ECPV_PUBLIC_KEY = self._generate_ecpv_keypair()

        ECPV_RC4_PRIVATE_KEY, ECPV_RC4_PUBLIC_KEY = self._generate_ecpv_keypair(
            curve='brainpoolP384r1')

        RSA_PRIVATE_KEY_1, RSA_PUBLIC_KEY_1, _ = self._generate_rsa_keypair(bits=4096)
        RSA_PRIVATE_KEY_2, RSA_PUBLIC_KEY_2, _ = self._generate_rsa_keypair(bits=4096)

        CONTROL_RSA_PRIVATE_KEY, CONTROL_RSA_PUBLIC_KEY, KEY1 = self._generate_rsa_keypair()
        CLIENT_RSA_PRIVATE_KEY, CLIENT_RSA_PUBLIC_KEY, KEY2 = self._generate_rsa_keypair()

        CONTROL_RSA_PRIVATE_KEY_CLIENT, CONTROL_RSA_PUBLIC_KEY_CLIENT, KEY3 = self._generate_rsa_keypair()
        CLIENT_RSA_PRIVATE_KEY_CLIENT, CLIENT_RSA_PUBLIC_KEY_CLIENT, KEY4 = self._generate_rsa_keypair()

        SSL_CA_PRIVATE_KEY, SSL_CA_CERTIFICATE, CAKEY, CACERT = self._generate_ssl_ca()
        CONTROL_SSL_BIND_KEY, CONTROL_SSL_BIND_CERTIFICATE = self._generate_ssl_keypair(KEY1, CAKEY, CACERT)
        CLIENT_SSL_BIND_KEY, CLIENT_SSL_BIND_CERTIFICATE = self._generate_ssl_keypair(
            KEY2, CAKEY, CACERT, role='CLIENT', serial=3)

        CONTROL_SSL_CLIENT_KEY, CONTROL_SSL_CLIENT_CERTIFICATE = self._generate_ssl_keypair(
            KEY3, CAKEY, CACERT, client=True, serial=4)
        CLIENT_SSL_CLIENT_KEY, CLIENT_SSL_CLIENT_CERTIFICATE = self._generate_ssl_keypair(
            KEY4, CAKEY, CACERT, role='CLIENT', client=True, serial=5)

        credentials = {
            'SCRAMBLESUIT_PASSWD': self._generate_scramblesuit_passwd(),
            'BIND_PAYLOADS_PASSWORD': self._generate_bind_payloads_password(),
            'CONTROL_RSA_PUB_KEY': CONTROL_RSA_PUBLIC_KEY,
            'CLIENT_RSA_PUB_KEY': CLIENT_RSA_PUBLIC_KEY,
            'CONTROL_RSA_PRIV_KEY': CONTROL_RSA_PRIVATE_KEY,
            'CLIENT_RSA_PRIV_KEY': CLIENT_RSA_PRIVATE_KEY,
            'CONTROL_SSL_BIND_CERT': CONTROL_SSL_BIND_CERTIFICATE,
            'CLIENT_SSL_BIND_CERT': CLIENT_SSL_BIND_CERTIFICATE,
            'CONTROL_SSL_BIND_KEY': CONTROL_SSL_BIND_KEY,
            'CLIENT_SSL_BIND_KEY': CLIENT_SSL_BIND_KEY,
            'CONTROL_SSL_CLIENT_CERT': CONTROL_SSL_CLIENT_CERTIFICATE,
            'CLIENT_SSL_CLIENT_CERT': CLIENT_SSL_CLIENT_CERTIFICATE,
            'CONTROL_SSL_CLIENT_KEY': CONTROL_SSL_CLIENT_KEY,
            'CLIENT_SSL_CLIENT_KEY': CLIENT_SSL_CLIENT_KEY,
            'SSL_CA_CERT': SSL_CA_CERTIFICATE,
            'SSL_CA_KEY': SSL_CA_PRIVATE_KEY,
            'CONTROL_DNSCNC_PRIV_KEY': ECPV_PRIVATE_KEY,
            'CLIENT_DNSCNC_PUB_KEY': ECPV_PUBLIC_KEY,
            'CONTROL_SIMPLE_RSA_PRIV_KEY': RSA_PRIVATE_KEY_1,
            'CLIENT_SIMPLE_RSA_PUB_KEY': RSA_PUBLIC_KEY_1,
            'CLIENT_SIMPLE_RSA_PRIV_KEY': RSA_PRIVATE_KEY_2,
            'CONTROL_SIMPLE_RSA_PUB_KEY': RSA_PUBLIC_KEY_2,
            'ECPV_RC4_PRIVATE_KEY': ECPV_RC4_PRIVATE_KEY,
            'ECPV_RC4_PUBLIC_KEY': ECPV_RC4_PUBLIC_KEY,
        }

        try:
            makedirs(path.dirname(self.USER_CONFIG))
        except OSError as e:
            if not e.errno == errno.EEXIST:
                raise

        with open(self.USER_CONFIG, 'w') as user_config:
            chmod(self.USER_CONFIG, 0600)

            for k, v in sorted(credentials.iteritems()):
                if '\n' in v:
                    user_config.write('{}={}\n'.format(k, repr(v)))
                else:
                    user_config.write('{}={}\n'.format(k, repr(v)))

if __name__ == '__main__':
    credentials = Credentials()
    credentials._generate(force=True)
