# -*- encoding: utf-8 -*-

__all__ = (
    'NetCreds',
    'add_cred', 'add_cred_for_uri', 'find_creds',
    'find_first_cred', 'find_all_creds', 'find_creds_for_uri',
    'export'
)

from socket import getaddrinfo, gaierror
from urlparse import urlparse

from netaddr import IPAddress, AddrFormatError

_TARGET_WEIGHTS = {
    'domain': 0b1, 'schema': 0b10,
    'realm': 0b100, 'port': 0b1000, 'path': 0b10000,
    'hostname': 0b100000, 'username': 0b1000000,
    'password': 0b10000000
}


def resolve_ip(hostname, port=0):
    ips = set()
    try:
        for addr in getaddrinfo(hostname, port):
            _, _, _, _, endpoint = addr
            ips.add(endpoint[0])

    except gaierror:
        return None

    return ips


def are_different(first, second):
    if not first or not second:
        return False

    if type(first) is not set and type(second) is set:
        if first not in second:
            return True

    elif type(first) is set and type(second) is not set:
        if second not in first:
            return True

    elif type(first) is set and type(second) is set:
        for x in first:
            if x in second:
                return False

    return first != second


class AuthInfo(object):
    __slots__ = (
        'username', 'password', 'domain', 'schema',
        'hostname', 'ip', 'port', 'realm', 'path',
        'custom'
    )

    def __init__(
        self, username, password=None, domain=None, schema=None,
            address=None, ip=None, port=None, realm=None,
            path=False, custom=None):

        self.password = password
        self.schema = schema
        self.port = port
        self.realm = realm
        self.path = path
        self.custom = custom

        self.hostname = None
        self.ip = None

        if domain is True:
            if '\\' in username:
                self.domain, self.username = username.split('\\')
            else:
                self.domain = None
                self.username = username
        else:
            self.domain = domain
            self.username = username

        try:
            self.ip = {IPAddress(address)}
            self.hostname = None
        except AddrFormatError:
            self.ip = None
            self.hostname = address

        if self.port:
            self.port = int(self.port)

        if self.ip is None and self.hostname:
            self.ip = resolve_ip(self.hostname, self.port)

    def _weight(self, available_fields):
        value = 0b0

        for field, weight in _TARGET_WEIGHTS.iteritems():
            if field not in available_fields:
                continue

            if getattr(self, field):
                value |= weight

        return value

    def __eq__(self, other):
        if type(other) != type(self):
            return False

        return all(
            getattr(self, key) == getattr(other, key)
            for key in self.__slots__
        )

    def __hash__(self):
        rethash = 0
        for key in self.__slots__:
            if key == 'custom':
                continue

            value = getattr(self, key)

            if type(value) == set:
                for item in value:
                    rethash <<= 1
                    rethash ^= hash(item)
            else:
                rethash <<= 1
                rethash ^= hash(value)

        for key in self.custom:
            rethash <<= 1
            rethash ^= hash(self.custom[key])

        return rethash

    @property
    def user(self):
        if self.domain:
            return self.domain + '\\' + self.username

        return self.username

    def __getattr__(self, key):
        if self.custom and key in self.custom:
            return self.custom[key]

    def as_dict(self):
        result = {
            key: getattr(self, key) for key in self.__slots__
            if key != 'custom' and getattr(self, key)
        }

        result['user'] = self.user

        result.update(self.custom)
        return result

    def as_tuple(self):
        return tuple(
            (k, tuple(str(x) for x in v) if hasattr(v, '__iter__') else v)
            for k,v in self.as_dict().iteritems()
        )


class NetCreds(object):
    __slots__ = ('creds',)

    default_creds_manager = None

    def __init__(self):
        self.creds = set()

    @staticmethod
    def get_default_creds_manager():
        if NetCreds.default_creds_manager is None:
            NetCreds.default_creds_manager = NetCreds()

        return NetCreds.default_creds_manager

    def add_cred(
        self, username, password=None, domain=None, schema=None,
            hostname=None, ip=None, port=None, realm=None, path=None, **kwargs):

        if port is not None:
            port = int(port)

        if schema is not None:
            schema = schema.lower()

        if hostname is not None:
            hostname = hostname.lower()

        if realm is not None:
            realm = realm.upper()

        if isinstance(domain, (str, unicode)):
            domain = domain.lower()

        self.creds.add(
            AuthInfo(
                username, password, domain, schema,
                hostname, ip, port, realm, path, kwargs))

    def add_uri(self, uri, password=None, username=None, realm=None):
        parsed = urlparse(uri)
        self.creds.add(
            AuthInfo(
                username or parsed.username,
                password or parsed.password,
                True, parsed.scheme, parsed.hostname,
                parsed.port, realm
            )
        )

    def find_creds_for_uri(self, authuri, username=None, realm=None, domain=None):
        parsed = urlparse(authuri)
        for cred in self.find_creds(
            parsed.scheme, parsed.hostname, parsed.port, username or parsed.username,
                realm, domain, parsed.path):

            yield cred

    def find_creds(
        self, schema=None, address=None, port=None, username=None, realm=None,
            domain=None, path=None):

        if address is not None:
            try:
                ip = {IPAddress(address)}
                hostname = None
            except AddrFormatError:
                ip = resolve_ip(address, port)
                hostname = address
        else:
            ip = None
            hostname = None

        if port:
            port = int(port)

        if username is not None:
            if '\\' in username and domain is None:
                domain, username = username.split('\\', 1)

        if port is not None:
            port = int(port)

        if schema is not None:
            schema = schema.lower()

        if address is not None:
            address = address.lower()

        if realm is not None:
            realm = realm.upper()

        if isinstance(domain, (str, unicode)):
            domain = domain.lower()

        fields = {
            'realm': realm,
            'domain': domain,
            'schema': schema,
            'ip': ip,
            'hostname': hostname,
            'port': port,
            'username': username,
        }

        available_fields = tuple(
            field for field in fields if fields[field]
        )

        sorted_creds = sorted(
            self.creds,
            key=lambda x: x._weight(available_fields), reverse=True
        )

        for cred in sorted_creds:
            pairs = tuple(
                (fields[field], getattr(cred, field)) for field in fields
            )

            different = False

            for (first, second) in pairs:
                if are_different(first, second):
                    different = True
                    break

            if path is not None and cred.path is not None:
                these_parts = '/'.join(
                    x for x in path.split('/') if x
                )

                those_parts = '/'.join(
                    x for x in cred.path.split('/') if x
                )

                if len(these_parts) < len(those_parts):
                    different = True
                else:
                    for x, y in zip(these_parts, those_parts):
                        if x != y:
                            different = True
                            break

            if different:
                continue

            yield cred

    # Urllib2 HTTPPasswordMgr
    def find_user_password(self, realm, authuri):
        for cred in self.find_creds(authuri, realm=realm):
            return cred.password

    def add_password(self, realm, uri, user, passwd):
        self.add_cred(uri, passwd, user, realm)


def add_cred(
    username, password=None, domain=None, schema=None,
       hostname=None, ip=None, port=None, realm=None, path=None, **kwargs):

    manager = NetCreds.get_default_creds_manager()
    manager.add_cred(
        username, password, domain, schema, hostname,
        ip, port, realm, path, **kwargs
    )


def add_cred_for_uri(username, password, authuri, realm=None):
    manager = NetCreds.get_default_creds_manager()
    manager.add_uri(authuri, password, username, realm)


def find_creds(
    schema=None, address=None, port=None, username=None, realm=None,
        domain=None, path=None):

    manager = NetCreds.get_default_creds_manager()
    for cred in manager.find_creds(
            schema, address, port, username, realm, domain, path):
        yield cred


def remove_creds(
    schema=None, address=None, port=None, username=None, realm=None,
        domain=None, path=None):

    manager = NetCreds.get_default_creds_manager()
    to_remove = set()

    for cred in manager.find_creds(
            schema, address, port, username, realm, domain, path):
        to_remove.add(cred)

    for cred in to_remove:
        manager.creds.remove(cred)


def clear_creds():
    manager = NetCreds.get_default_creds_manager()
    manager.creds.clear()


def find_first_cred(
    schema=None, address=None, port=None, username=None, realm=None,
        domain=None, path=None):

    manager = NetCreds.get_default_creds_manager()
    for cred in manager.find_creds(
            schema, address, port, username, realm, domain, path):
        return cred

def find_all_creds(
    schema=None, address=None, port=None, username=None, realm=None,
        domain=None, path=None, as_tuple=False):

    result = []

    for cred in find_creds(
        schema=None, address=None, port=None, username=None,
            realm=None, domain=None, path=None):

        if as_tuple:
            result.append(cred.as_tuple())
        else:
            result.append(cred)

    return tuple(result)


def find_creds_for_uri(authuri, username=None, realm=None, domain=None):
    manager = NetCreds.get_default_creds_manager()
    for cred in manager.find_creds_for_uri(authuri, username, realm, domain):
        yield cred


def export():
    manager = NetCreds.get_default_creds_manager()
    return tuple(x.as_tuple() for x in manager.creds)
