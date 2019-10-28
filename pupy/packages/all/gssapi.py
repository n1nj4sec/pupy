# -*- coding: utf-8 -*-
# gssapi-like wrapper over ccs-pykerberos and winkerberos
# enough to run ldap3 auth, no more

import sys

if sys.platform == 'win32':
    import winkerberos as krb
    NTLM = krb.GSS_MECH_OID_NTLM
else:
    import kerberos as krb
    NTLM = None

from base64 import b64encode, b64decode


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
        'name', 'usage'
    )

    def __init__(self, name=None, usage=None):
        self.name = name
        self.usage = usage
    

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
    
    def step(self, in_token):
        if not self._ctx:
            print "SERVER:", self.name
            print "PRINCIPAL:", self.creds.name if self.creds else None
            print "MECH", self.mech

            result, self._ctx = krb.authGSSClientInit(
                self.name, self.creds.name if self.creds else None,
                gssflags=krb.GSS_C_SEQUENCE_FLAG | krb.GSS_C_MUTUAL_FLAG,
                mech_oid=self.mech
            )

            if result < 0:
                raise GSSAPIAdapterException(result)

            result = krb.authGSSClientInquireCred(self._ctx)
            if result < 0:
                raise GSSAPIAdapterException(result)

        in_token = b64encode(in_token) if in_token else ''
        print "in_token: ", in_token
        try:
            result = krb.authGSSClientStep(
                self._ctx, in_token
            )
        except krb.GSSError as e:
            _, (_, code) = e.args
            if code == 100001:
                self.complete = True
                return

            raise

        if result < 0:
            raise GSSAPIAdapterException(result)

        self.complete = result == krb.AUTH_GSS_COMPLETE
        print "Complete?", self.complete
        out_token = krb.authGSSClientResponse(self._ctx)
        print "out_token:", out_token
        return b64decode(out_token) if out_token else ''

    def wrap(self, data, protect=None):
        if data:
            data = b64encode(data)

        result = krb.authGSSClientWrap(
            self._ctx, data, None, 0
        )
        print "WRAP", data, protect, result

        if result < 0:
            raise GSSAPIAdapterException(result)

        out_data = krb.authGSSClientResponse(self._ctx)
        print "out_data:", out_data
        return WrappedToken(b64decode(out_data))

    def unwrap(self, data):
        if data:
            data = b64encode(data)

        result = krb.authGSSClientUnwrap(self._ctx, data)

        print "UNWRAP", data, result

        if result < 0:
            raise GSSAPIAdapterException(result)

        out_data =  krb.authGSSClientResponse(self._ctx)
        print "out_data:", out_data
        return WrappedToken(b64decode(out_data))
