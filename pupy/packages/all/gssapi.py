# -*- coding: utf-8 -*-
# gssapi-like wrapper over ccs-pykerberos and winkerberos
# enough to run ldap3 auth, no more

import sys
import logging

logger = logging.getLogger().getChild('gssapi_wrap')

if sys.platform == 'win32':
    import winkerberos as krb
    NTLM = krb.GSS_MECH_OID_NTLM
    logger.info('Using WinKerberos')
else:
    import kerberos as krb
    logger.info('Using PyKerberos')
    NTLM = None

from base64 import b64encode, b64decode

class ExtPassword(tuple):
    @property
    def username(self):
        return self[0]

    @property
    def password(self):
        return self[1]

    def __str__(self):
        return self[0]


GSSAPI_EXT_PASSWORD = ExtPassword


class GSSAPIAdapterException(Exception):
    pass


class exceptions(object):
    MissingContextError = GSSAPIAdapterException
    GSSError = krb.GSSError


class NameType(object):
    hostbased_service = 0


class MechType(object):
    kerberos = krb.GSS_MECH_OID_KRB5
    spnego = krb.GSS_MECH_OID_SPNEGO
    ntlm = NTLM


class WrappedToken(object):
    __slots__ = ('message',)

    def __init__(self, message):
        self.message = message


def Name(name, *args, **kwargs):
    return name


class Credentials(object):
    __slots__ = (
        'name', 'usage', 'password'
    )

    def __init__(self, name=None, usage=None, password=None):
        self.name = name
        self.password = None
        self.usage = usage

        if isinstance(name, GSSAPI_EXT_PASSWORD):
            self.name = name.username
            self.password = name.password
        else:
            self.name = name
            self.password = None

    def __repr__(self):
        return 'Credentials(name={}, usage={}, password={})'.format(
            self.name, self.usage, self.password
        )


class SecurityContext(object):
    __slots__ = (
        'name', 'mech', 'creds', 'complete',
        '_ctx'
    )

    def __init__(self, name=None, mech=None, creds=None):
        self.name = name
        self.mech = mech
        self.creds = creds
        self.complete = False
        self._ctx = None

        if __debug__:
            logger.debug('New security context: %s', self)

    def __repr__(self):
        return self.__class__.__name__ + \
            '(name={}, mech={}, creds={}, complete={})'.format(
                self.name, self.mech, self.creds, self.complete)

    def step(self, in_token):
        if not self._ctx:
            if __debug__:
                logger.debug('Initialize security context: %s', self)

            args = [
                self.name,
                self.creds.name if self.creds else None
            ]

            kwargs = {
                'gssflags': krb.GSS_C_SEQUENCE_FLAG | krb.GSS_C_MUTUAL_FLAG,
                'mech_oid': self.mech
            }

            need_inquire_creds = True

            if self.creds and self.creds.password:
                kwargs['password'] = self.creds.password,

                try:
                    result, self._ctx = krb.authGSSClientInit(
                        *args, **kwargs
                    )

                    logger.debug('GSSApiExt: password ok')
                    need_inquire_creds = False
                except TypeError:
                    logger.debug('GSSApiExt: password is not supported')
                    del kwargs['password']

            if not self._ctx:
                result, self._ctx = krb.authGSSClientInit(
                    *args, **kwargs
                )

            if result < 0:
                raise GSSAPIAdapterException(result)

            if need_inquire_creds:
                logger.debug('GSSApiExt: inquire credentials')
                result = krb.authGSSClientInquireCred(self._ctx)
                if result < 0:
                    raise GSSAPIAdapterException(result)

        in_token = b64encode(in_token) if in_token else ''

        result = krb.authGSSClientStep(
            self._ctx, in_token
        )
        if result < 0:
            raise GSSAPIAdapterException(result)

        self.complete = result == krb.AUTH_GSS_COMPLETE
        out_token = krb.authGSSClientResponse(self._ctx)
        return b64decode(out_token) if out_token else ''

    def wrap(self, data, protect=None):
        if data:
            data = b64encode(data)

        result = krb.authGSSClientWrap(
            self._ctx, data, None, 0
        )

        if result < 0:
            raise GSSAPIAdapterException(result)

        out_data = krb.authGSSClientResponse(self._ctx)
        return WrappedToken(b64decode(out_data))

    def unwrap(self, data):
        if data:
            data = b64encode(data)

        result = krb.authGSSClientUnwrap(self._ctx, data)

        if result < 0:
            raise GSSAPIAdapterException(result)

        out_data = krb.authGSSClientResponse(self._ctx)
        return WrappedToken(b64decode(out_data))
