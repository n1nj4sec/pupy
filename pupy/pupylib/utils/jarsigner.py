# -*- coding: utf-8 -*-

from M2Crypto import X509, EVP, RSA, BIO, m2

from zipfile import ZipFile, ZIP_DEFLATED
from hashlib import sha1
from base64 import b64encode

def jarsigner(pem_priv, pem_cert, apk_path, dest_fileobj):
    pk = EVP.PKey()

    if type(pem_priv) == unicode:
        pem_priv = pem_priv.encode('utf-8')

    if type(pem_cert) == unicode:
        pem_cert = pem_cert.encode('utf-8')

    pk.assign_rsa(RSA.load_key_string(pem_priv))
    cert = X509.load_cert_string(pem_cert)

    MANIFEST_MF = \
      'Manifest-Version: 1.0\r\n' \
      'Created-By: 9.0.4 (Oracle Corporation)\r\n' \
      '\r\n'

    SHA1_MAIN_ATTRIBUTES = b64encode(sha1(MANIFEST_MF).digest())

    SIGNER_SF = ''

    with ZipFile(apk_path) as infile:
        with ZipFile(dest_fileobj, "w", ZIP_DEFLATED) as outfile:
            for name in infile.namelist():
                if name.startswith('META-INF'):
                    continue

                content = infile.read(name)
                digest = sha1(content)
                outfile.writestr(name, content)

                manifest_record = 'Name: {}\r\nSHA1-Digest: {}\r\n\r\n'.format(
                    name, b64encode(digest.digest())
                )

                MANIFEST_MF += manifest_record

                sf_record = 'Name: {}\r\nSHA1-Digest: {}\r\n\r\n'.format(
                    name, b64encode(sha1(manifest_record).digest())
                )

                SIGNER_SF += sf_record

            SIGNER_SF = \
              'Signature-Version: 1.0\r\n' \
              'Created-By: 9.0.4 (Oracle Corporation)\r\n' \
              'SHA1-Digest-Manifest: {}\r\n' \
              'SHA1-Digest-Manifest-Main-Attributes: {}\r\n'\
              '\r\n'.format(
                  b64encode(sha1(MANIFEST_MF).digest()),
                  SHA1_MAIN_ATTRIBUTES
            ) + SIGNER_SF

            outfile.writestr('META-INF/MANIFEST.MF', MANIFEST_MF)
            outfile.writestr('META-INF/SIGNER.SF', SIGNER_SF)

            buf = BIO.MemoryBuffer(SIGNER_SF)
            sign = BIO.MemoryBuffer()

            p7 = m2.pkcs7_sign0(
                cert._ptr(), pk._ptr(),
                buf._ptr(), m2.sha1(), m2.PKCS7_DETACHED | m2.PKCS7_NOATTR)
            m2.pkcs7_write_bio_der(p7, sign._ptr())
            m2.pkcs7_free(p7)

            outfile.writestr('META-INF/SIGNER.RSA', sign.read())
