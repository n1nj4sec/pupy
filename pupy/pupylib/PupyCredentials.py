# -*- coding: utf-8-*-

if __name__ == '__main__':
    import sys
    sys.path.append('..')

from PupyConfig import PupyConfig

from os import path, urandom, chmod, makedirs, unlink

import logging
import string
import errno
import time

from network.transports import *
from network.lib.picocmd.ecpv import ECPV
from getpass import getpass

from M2Crypto import X509, EVP, RSA, ASN1, BIO
import rsa

DEFAULT_ROLE='CLIENT'

class EncryptionError(Exception):
    pass

# http://stackoverflow.com/questions/16761458/how-to-aes-encrypt-decrypt-files-using-python-pycrypto-in-an-openssl-compatible
# M2Crypto simply generate garbage instead of AES.. Crazy situation

from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random
from StringIO import StringIO

try:
    import secretstorage
except:
    pass

class GnomeKeyring(object):
    def __init__(self):
        try:
            self.bus = secretstorage.dbus_init()
        except:
            self.bus = None

        self.collection = {'application':'pupy'}

    def get_pass(self):
        if not self.bus:
            return

        try:
            collection = secretstorage.get_default_collection(self.bus)
            if collection.is_locked():
                collection.unlock() # will open a gnome-keyring popup
            x=collection.search_items(self.collection).next()
            return x.get_secret()

        except StopIteration:
            pass

        except Exception as e:
            logging.warning("Error with GnomeKeyring get_pass : %s"%e)

    def store_pass(self, password):
        if not self.bus:
            return

        try:
            collection = secretstorage.get_default_collection(self.bus)
            if collection.is_locked():
                collection.unlock()
            collection.create_item('pupy_credentials', self.collection, password)
        except Exception as e:
            logging.warning("Error with GnomeKeyring store_pass : %s"%e)

    def del_pass(self):
        if not self.bus:
            return

        collection = secretstorage.get_default_collection(self.bus)
        if collection.is_locked():
            collection.unlock()
        x=collection.search_items(self.collection).next()
        x.delete()

class Encryptor(object):
    _instance = None
    _getpass = getpass

    def __init__(self, password):
        self.password = password

    @staticmethod
    def initialized():
        return not ( Encryptor._instance is None )

    @staticmethod
    def instance(password=None, getpass_hook=None, config=None):
        if not Encryptor._instance:
            if not password:
                config = config or PupyConfig()
                use_gnome_keyring = config.getboolean('pupyd', 'use_gnome_keyring')

                if use_gnome_keyring:
                    gkr = GnomeKeyring()
                    password = gkr.get_pass()

                if not password:
                    getpass_hook = getpass_hook or getpass
                    if use_gnome_keyring:
                        print '[I] use_gnome_keyring is true, the password will be stored in the Gnome-Keyring'

                    password = getpass_hook('[I] Credentials password: ')
                    if use_gnome_keyring:
                        gkr.store_pass(password)

            Encryptor._instance = Encryptor(password)

        return Encryptor._instance

    def derive_key_and_iv(self, salt, key_length, iv_length):
        d = d_i = ''
        while len(d) < key_length + iv_length:
            d_i = md5(d_i + self.password + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length+iv_length]

    def encrypt(self, in_file, out_file, key_length=32):
        bs = AES.block_size
        salt = Random.new().read(bs - len('Salted__'))
        key, iv = self.derive_key_and_iv(salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out_file.write('Salted__' + salt)
        finished = False
        while not finished:
            chunk = in_file.read(1024 * bs)
            if len(chunk) == 0 or len(chunk) % bs != 0:
                padding_length = bs - (len(chunk) % bs)
                chunk += padding_length * chr(padding_length)
                finished = True
            out_file.write(cipher.encrypt(chunk))

    def decrypt(self, in_file, out_file, key_length=32):
        bs = AES.block_size
        salt = in_file.read(bs)[len('Salted__'):]
        key, iv = self.derive_key_and_iv(salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = ''
        finished = False
        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
            if len(next_chunk) == 0:
                padding_length = ord(chunk[-1])
                if padding_length < 1 or padding_length > bs:
                   try:
                       GnomeKeyring().del_pass() # to avoid keep using a bad credential
                   except:
                       pass
                   raise ValueError("bad decrypt pad (%d)" % padding_length)
                # all the pad-bytes must be the same
                if chunk[-padding_length:] != (padding_length * chr(padding_length)):
                   # this is similar to the bad decrypt:evp_enc.c from openssl program
                   raise ValueError("bad decrypt")
                chunk = chunk[:-padding_length]
                finished = True
            out_file.write(chunk)

ENCRYPTOR = Encryptor.instance

class Credentials(object):
    SYSTEM_CONFIG = path.join(path.dirname(__file__), '..', 'crypto', 'credentials.py')

    def __init__(self, role=None, password=None, config=None):
        config = config or PupyConfig()
        configfile = path.join(config.get_folder('crypto'), 'credentials.py')

        self._generate(password=password, configfile=configfile)

        configfiles = [ self.SYSTEM_CONFIG, configfile ]

        role = role or DEFAULT_ROLE
        self.role = role.upper() if role else 'ANY'

        if not self.role in ('CONTROL', 'CLIENT'):
            raise ValueError('Unsupported role: {}'.format(self.role))

        self._credentials = {}
        for configfile in configfiles:
            if path.exists(configfile):
                with open(configfile, 'rb') as creds:
                    content = creds.read()
                    if not content:
                        raise ValueError('Corrupted file: {}'.format(configfile))

                    if content.startswith('Salted__'):
                        if not ENCRYPTOR:
                            raise EncryptionError(
                                'Encrpyted credential storage: {}'.format(configfile)
                            )

                        fcontent = StringIO()
                        encryptor = ENCRYPTOR(password=password, config=config)
                        encryptor.decrypt(StringIO(content), fcontent)
                        content = fcontent.getvalue()

                    exec content in self._credentials

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
        cert.sign(pk, 'sha256')

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
        cert.sign(ca_key, 'sha256')

        return pk.as_pem(cipher=None), cert.as_pem()

    def _generate(self, force=False, password=None, configfile=None):
        if path.exists(configfile) and not force:
            return

        configdir = path.dirname(configfile)

        logging.warning("Generating credentials to {}".format(configfile))

        ECPV_PRIVATE_KEY, ECPV_PUBLIC_KEY = self._generate_ecpv_keypair()

        CONTROL_ECPV_RC4_PRIVATE_KEY, CONTROL_ECPV_RC4_PUBLIC_KEY = self._generate_ecpv_keypair(
            curve='brainpoolP384r1')
        CLIENT_ECPV_RC4_PRIVATE_KEY, CLIENT_ECPV_RC4_PUBLIC_KEY = self._generate_ecpv_keypair(
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
            'CONTROL_ECPV_RC4_PRIVATE_KEY': CONTROL_ECPV_RC4_PRIVATE_KEY,
            'CONTROL_ECPV_RC4_PUBLIC_KEY': CONTROL_ECPV_RC4_PUBLIC_KEY,
            'CLIENT_ECPV_RC4_PRIVATE_KEY': CLIENT_ECPV_RC4_PRIVATE_KEY,
            'CLIENT_ECPV_RC4_PUBLIC_KEY': CLIENT_ECPV_RC4_PUBLIC_KEY,
        }

        try:
            makedirs(path.dirname(configfile))
        except OSError as e:
            if not e.errno == errno.EEXIST:
                raise

        with open(configfile, 'wb') as user_config:
            chmod(configfile, 0600)
            content = '\n'.join([
                '{}={}\n'.format(k, repr(v)) for k,v in credentials.iteritems()
            ]) + '\n'

            if ENCRYPTOR:
                encryptor = ENCRYPTOR(password=password)
                encryptor.encrypt(StringIO(content), user_config)
            else:
                user_config.write(content)

if __name__ == '__main__':
    credentials = Credentials()
    credentials._generate(force=True)
