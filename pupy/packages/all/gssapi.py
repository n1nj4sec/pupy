# -*- coding: utf-8 -*-
# gssapi-like wrapper over ccs-pykerberos and winkerberos
# enough to run ldap3 auth, no more

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import sys
import logging
from functools import reduce

logger = logging.getLogger().getChild('gssapi_wrap')

if sys.platform == 'win32':
    import winkerberos as krb
    have_inquire_creds = False
    logger.info('Using WinKerberos')
else:
    import kerberos as krb
    logger.info('Using PyKerberos')
    have_inquire_creds = True

from base64 import b64encode, b64decode

C_NT_HOSTBASED_SERVICE = 0

C_PROT_READY_FLAG = getattr(krb, 'GSS_C_PROT_READY_FLAG', 0)
C_SEQUENCE_FLAG = krb.GSS_C_SEQUENCE_FLAG
C_INTEG_FLAG = krb.GSS_C_INTEG_FLAG
C_MUTUAL_FLAG = krb.GSS_C_MUTUAL_FLAG
C_DELEG_FLAG = krb.GSS_C_DELEG_FLAG


class OID(object):
    __slots__ = ()

    @staticmethod
    def mech_from_string(mech):

        if mech == '1.2.840.113554.1.2.2':
            return krb.GSS_MECH_OID_KRB5
        elif mech == '1.3.6.1.5.5.2':
            return krb.GSS_MECH_OID_SPNEGO
        else:
            raise NotImplementedError(
                'Unsupported mech {}'.format(mech))


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
GSSAPI_MIC_SUPPORT = hasattr(krb, 'authGSSSign')

GSSException = krb.GSSError


class GSSAPIAdapterException(Exception):
    pass


class RequirementFlag(object):
    protection_ready = C_PROT_READY_FLAG
    integrity = C_INTEG_FLAG
    mutual_authentication = C_MUTUAL_FLAG
    delegate_to_peer = C_DELEG_FLAG


class exceptions(object):
    MissingContextError = GSSAPIAdapterException
    GSSError = GSSException
    GeneralError = GSSAPIAdapterException


class raw(object):
    misc = exceptions


class NameType(object):
    hostbased_service = 0


class MechType(object):
    kerberos = krb.GSS_MECH_OID_KRB5
    spnego = krb.GSS_MECH_OID_SPNEGO


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


class Context(object):
    __slots__ = (
        'name', 'mech', 'creds', 'complete', 'flags', 'usage',
        '_ctx'
    )

    def __init__(self, name=None, mech=None, creds=None, flags=0, usage=None):
        if hasattr(flags, '__iter__') and not isinstance(flags, str):
            flags = reduce(lambda x, y: x|y, flags, 0)

        self.name = name or ''
        self.mech = mech or krb.GSS_MECH_OID_KRB5
        self.creds = creds
        self.complete = False
        self.flags = flags or C_SEQUENCE_FLAG | C_MUTUAL_FLAG
        self.usage = usage
        self._ctx = None

        if __debug__:
            logger.debug('New security context: %s', self)

    def __repr__(self):
        return self.__class__.__name__ + \
            '(name={}, mech={}, creds={}, complete={})'.format(
                self.name, self.mech, self.creds, self.complete)

    def init(self):
        if self._ctx:
            return self._ctx

        if __debug__:
            logger.debug('Initialize security context: %s', self)

        args = [
            self.name,
            self.creds.name if self.creds else None
        ]

        kwargs = {
            'gssflags': self.flags,
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

        if need_inquire_creds and have_inquire_creds:
            logger.debug('GSSApiExt: inquire credentials')
            result = krb.authGSSClientInquireCred(self._ctx)
            if result < 0:
                raise GSSAPIAdapterException(result)

    @property
    def established(self):
        return self.complete

    def step(self, in_token):
        if not self._ctx:
            self.init()

        in_token = b64encode(in_token) if in_token else ''

        result = krb.authGSSClientStep(
            self._ctx, in_token
        )
        if result < 0:
            raise GSSAPIAdapterException(result)

        self.complete = result == krb.AUTH_GSS_COMPLETE
        out_token = krb.authGSSClientResponse(self._ctx)
        return b64decode(out_token) if out_token else None

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

    def sign(self, sid):
        return b64decode(krb.authGSSSign(self._ctx, b64encode(sid)))

    get_signature = sign

    def verify_mic(self, sid, token):
        krb.authGSSVerify(self._ctx, b64encode(sid), b64encode(token))

    verify_signature = verify_mic


class SecurityContext(Context):
    pass


def InitContext(peer_name=None, mech_type=None, req_flags=None):
    context = Context(name=peer_name, mech=mech_type, flags=req_flags)
    context.init()
    return context
