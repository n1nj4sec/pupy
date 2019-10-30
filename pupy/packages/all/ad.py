# -*- coding: utf-8 -*-

# Stolen from ldapdomaindump

from ldap3 import (
    Server, Connection, SIMPLE, ALL, BASE, SUBTREE,
    SASL, NTLM, ALL_ATTRIBUTES, GSSAPI, RESTARTABLE
)

from ldap3.core.exceptions import (
    LDAPKeyError, LDAPAttributeError, LDAPCursorError, LDAPInvalidDnError,
    LDAPSocketOpenError, LDAPSocketReceiveError,
    LDAPUnknownAuthenticationMethodError
)

from ldap3.abstract import attribute, attrDef
from ldap3.utils import dn
from ldap3.utils.ciDict import CaseInsensitiveDict
from ldap3.protocol.controls import build_control

from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.type.univ import Sequence, OctetString, Integer

from socket import (
    getfqdn, socket, getaddrinfo,
    AF_UNSPEC, SOCK_DGRAM, SOCK_STREAM
)

from socket import error as socket_error
from sys import exc_info

from datetime import datetime
from threading import Thread, Event
from time import clock, mktime
from inspect import isgenerator
from hashlib import md5

from gssapi import exceptions as gssexceptions

try:
    from gssapi import GSSAPI_EXT_PASSWORD
except ImportError:
    GSSAPI_EXT_PASSWORD = False

try:
    import pupy
    from network.lib.netcreds import find_creds

    logger = pupy.get_logger('ad')
except ImportError:
    import logging
    logger = logging.getLogger()

    def find_creds(*args, **kwargs):
        return

try:
    import dnslib
    auto_discovery = True
except ImportError:
    auto_discovery = False


REALM_CACHE = {}

MINIMAL_COMPUTERATTRIBUTES = (
    'cn', 'sAMAccountName', 'dNSHostName', 'operatingSystem',
    'operatingSystemServicePack', 'operatingSystemVersion',
    'lastLogon', 'userAccountControl', 'whenCreated', 'objectSid',
    'description', 'objectClass'
)

MINIMAL_USERATTRIBUTES = (
    'cn', 'name', 'sAMAccountName', 'memberOf',
    'primaryGroupId', 'whenCreated', 'whenChanged',
    'lastLogon', 'userAccountControl', 'pwdLastSet',
    'objectSid', 'description', 'objectClass'
)

MINIMAL_GROUPATTRIBUTES = (
    'cn', 'name', 'sAMAccountName', 'memberOf', 'description',
    'whenCreated', 'whenChanged', 'objectSid', 'distinguishedName',
    'objectClass'
)


class SdFlags(Sequence):
    componentType = NamedTypes(NamedType('Flags', Integer()))


def build_sd_control(sdflags=0x04):
    sdcontrol = SdFlags()
    sdcontrol.setComponentByName('Flags', sdflags)
    return build_control('1.2.840.113556.1.4.801', True, sdcontrol)


class LDAPContext(object):
    __slots__ = (
        'server', 'connection', 'root'
    )

    def __init__(self, server, connection, root):
        self.server = server
        self.connection = connection
        self.root = root


class LDAPRequest(object):
    __slots__ = (
        '_filter', 'attributes', 'value', 'one',
        'minimal'
    )

    def __init__(
        self, filter,
            attributes=ALL_ATTRIBUTES, minimal=None,
            value=None, one=False):

        self._filter = filter
        self.attributes = attributes
        self.minimal = minimal
        self.value = value
        self.one = one

    def _get_result(self, result):
        if self.value:
            if not result:
                return None

            result = result[0][self.value]
            if self.one:
                return result.value
            else:
                return result.values

        return result

    def filter(self, custom_filter, kwargs):
        filter = self._filter

        if kwargs:
            filter = filter.format(**kwargs)

        if custom_filter:
            filter = '(&{}{})'.format(
                filter, custom_filter
            )

        return filter

    def __call__(self, ctx, custom_filter=None, minimal=False, **kwargs):
        filter = self.filter(custom_filter, kwargs)

        ctx.connection.search(
            ctx.root, filter,
            self.minimal if (
                minimal and self.minimal
            ) else self.attributes
        )

        try:
            return self._get_result(ctx.connection.entries)

        except (IndexError, LDAPKeyError):
            return self._get_result([])


class LDAPLargeRequest(LDAPRequest):
    __slots__ = ()

    def __call__(
        self, ctx, on_data, on_completed, interruption,
            page_size=64, custom_filter=None, minimal=False, **kwargs):

        filter = self.filter(custom_filter, kwargs)
        controls = []

        if 'ntsecuritydescriptor' in tuple(attr.lower() for attr in self.attributes):
            controls.append(build_sd_control())

        iterator = ctx.connection.extend.standard.paged_search(
            ctx.root, filter,
            attributes=self.minimal if (
                minimal and self.minimal) else self.attributes,
            paged_size=page_size, paged_criticality=True,
            controls=controls,
            generator=True
        )

        completed = False

        while not (completed or (interruption and interruption.is_set())):
            chunk = []

            for _ in xrange(page_size):
                try:
                    chunk.append(next(iterator))
                except StopIteration:
                    completed = True
                    break

            if chunk:
                if on_data:
                    chunk = self._get_result(chunk)
                    on_data(chunk)
                del chunk[:]

        if on_completed:
            on_completed()


ADUser = LDAPRequest(
    '(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))',
    ('cn', 'memberOf', 'primaryGroupId'),
)

ADAdmin = LDAPRequest(
    '''
        (&
            (objectCategory=person)
            (objectClass=user)
            (sAMAccountName={username})'
            (|
                (memberOf:1.2.840.113556.1.4.1941:={dagroup})'
                (memberOf:1.2.840.113556.1.4.1941:={eagroup}))
            )
        )
    ''',
    ('cn', 'sAMAccountName')
)

AllUsers = LDAPLargeRequest(
    '(&(objectCategory=person)(objectClass=user))',
    minimal=MINIMAL_USERATTRIBUTES
)

AllComputers = LDAPLargeRequest(
    '(&(objectCategory=computer)(objectClass=user))',
    minimal=MINIMAL_COMPUTERATTRIBUTES
)

AllSPNs = LDAPLargeRequest(
    '(&(objectCategory=computer)(objectClass=user)(servicePrincipalName=*))'
)

AllGroups = LDAPLargeRequest(
    '(objectClass=group)',
    minimal=MINIMAL_GROUPATTRIBUTES
)

DomainPolicy = LDAPLargeRequest(
    '(objectClass=domain)'
)

Trusts = LDAPLargeRequest(
    '(objectClass=trustedDomain)'
)

SecurityGroups = LDAPLargeRequest(
    '(groupType:1.2.840.113556.1.4.803:=2147483648)'
)

RootSid = LDAPRequest(
    '(objectClass=domain)', ['objectSid'], 'objectSid'
)

GroupMembers = LDAPLargeRequest(
    '(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={group}))',
    MINIMAL_USERATTRIBUTES
)

GroupDNFromId = LDAPRequest(
    '(objectSid={domain}-{gid})',
    ['distinguishedName'],
    'distinguishedName',
    True
)

IMM = 0
LIST = 1
MAP = 2
DATE = 3


# To fit into brine
def as_tuple_deep(obj):
    if isinstance(obj, (list, tuple)) or isgenerator(obj):
        return LIST, tuple(
            as_tuple_deep(child) for child in obj
        )
    elif isinstance(obj, dict):
        return MAP, tuple(
            (
                key, as_tuple_deep(value)
            ) for key, value in obj.viewitems()
        )
    elif isinstance(obj, CaseInsensitiveDict):
        return MAP, tuple(
            (k, as_tuple_deep(obj[k])) for k in obj
        )
    elif isinstance(obj, datetime):
        timetuple = obj.timetuple()
        if timetuple.tm_year < 1970:
            return DATE, 0
        return DATE, mktime(timetuple)
    elif hasattr(obj, '__slots__'):
        return MAP, tuple(
            (k,
                as_tuple_deep(getattr(obj, k))
            ) for k in obj.__slots__
        )
    else:
        return IMM, obj


class ADDumperException(Exception):
    pass


class ADLdapServer(object):
    __slots__ = (
        'port', 'priority', 'address'
    )

    def __init__(self, address, port, priority):
        if hasattr(address, 'label'):
            self.address = '.'.join(address.label)
        else:
            self.address = address

        self.port = port
        self.priority = priority

    def __le__(self, other):
        return self.priority.__le__(other.priority)

    def __cmp__(self, other):
        return self.priority.__cmp__(other.priority)

    def __repr__(self):
        return self.__class__.__name__ + '({}, {}, {})'.format(
            repr(self.address), repr(self.port), repr(self.priority)
        )


class ADCtx(object):
    __slots__ = (
        'realm', 'server', 'connection', 'root',
        '_interrupt', '_kwargs', '_timeout',

        '_i_am',
        '_ldap_servers', '_name_servers', '_ns_socket', '_ns_udp',
        '_preferred_name_server', '_preferred_ldap_server'
    )

    SIMPLE_DUMP_REQUESTS = {
        'groups': AllGroups,
        'users': AllUsers,
        'computers': AllComputers,
        'policy': DomainPolicy,
        'trusts': Trusts,
        'spns': AllSPNs,
        'security_groups': SecurityGroups
    }

    def _bootstrap_ns(self, timeout=1, first=False):
        query = dnslib.DNSRecord.question(self.realm, 'SOA')

        for addr in getaddrinfo(self.realm, 53):
            if self._interrupt.is_set():
                break

            family, kind, proto, _, endpoint = addr

            try:
                start = clock()
                s = socket(family, kind, proto)
                s.settimeout(timeout)
                s.connect(endpoint)
                s.send(query.pack())
                data = s.recv(4096)
                duration = clock() - start

                parsed = dnslib.DNSRecord.parse(data)
                if parsed.header.rcode != dnslib.RCODE.NOERROR:
                    continue

                self._name_servers.append((addr, duration))
                if first:
                    return True

            except socket_error:
                pass

            finally:
                s.close()

        return bool(self._name_servers)

    def _select_fastest_ns(self):
        if not self._name_servers:
            for timeout in (1, 5):
                if self._bootstrap_ns(timeout=timeout):
                    break

        if not self._name_servers:
            raise ValueError('No nameservers found')

        self._preferred_name_server, duration = sorted(
            self._name_servers, key=lambda (_, duration): duration
        )[0]

    def _broken_ns(self, ns):
        for known_ns in self._name_servers:
            if ns == known_ns[0]:
                self._name_servers.remove(known_ns)
                return

    def _resolve(self, address, qtype):
        retries = 0
        while not self._interrupt.is_set():
            family, kind, proto, _, addr = self._preferred_name_server

            if self._ns_socket is None:
                try:
                    self._ns_socket = socket(family, kind, proto)
                    self._ns_socket.connect(addr)
                except socket_error:
                    self._broken_ns(addr)
                    self._select_fastest_ns()
                    self._ns_socket.close()
                    self._ns_socket = None

                    retries += 1
                    if retries > 5:
                        raise ValueError('Too many retries')

                    continue

            query = dnslib.DNSRecord.question(address, qtype).pack()
            try:
                self._ns_socket.send(query)

                max_dns_size = 4096

                if kind == SOCK_STREAM:
                    max_dns_size = 65535

                response = self._ns_socket.recv(max_dns_size)
            except socket_error:
                self._broken_ns(addr)
                self._select_fastest_ns()
                self._ns_socket.close()
                self._ns_socket = None

                retries += 1
                if retries > 5:
                    if retries > 5:
                        raise ValueError('Too many retries')

                    continue

            parsed = dnslib.DNSRecord.parse(response)
            if parsed.header.rcode != dnslib.RCODE.NOERROR:
                return []

            return [
                record.rdata for record in parsed.rr
                if dnslib.QTYPE[record.rtype] == qtype
            ]

    def _autodiscovery(self, global_catalog=False):
        if not auto_discovery:
            raise ValueError('Autodiscovery is not available')

        self._select_fastest_ns()

        ldap_servers = self._resolve('_ldap._tcp.' + self.realm, 'SRV')
        if not ldap_servers:
            raise ValueError('LDAP Servers autodiscovery failed')

        _ldap_servers = []

        for ldap_server in ldap_servers:
            _ldap_servers.append(
                ADLdapServer(
                    ldap_server.target, ldap_server.port,
                    ldap_server.priority
                )
            )

        _ldap_servers = sorted(_ldap_servers)

        self._ldap_servers = []

        _gc_ldap_servers = []

        if global_catalog:
            gc_ldap_servers = self._resolve(
                '_ldap._tcp.gc._msdcs.' + self.realm, 'SRV')

            if gc_ldap_servers:
                for ldap_server in gc_ldap_servers:
                    _gc_ldap_servers.append(
                        ADLdapServer(
                            ldap_server.target, ldap_server.port,
                            ldap_server.priority
                        )
                    )

                _gc_ldap_servers = sorted(_gc_ldap_servers)

                # Global catalog has priority
                self._ldap_servers.extend(_gc_ldap_servers)

        self._ldap_servers.extend(_ldap_servers)

    def _try_connect_exact(
        self, ldap_server, global_catalog=False, recv_timeout=60,
            domain=None, user=None, password=None, authentication=None):

        kwargs = {
            'authentication': authentication,
            'auto_referrals': True,
            'use_referral_cache': True,
            'receive_timeout': self._timeout,
            'client_strategy': RESTARTABLE
        }

        if not (user and password) and authentication == SIMPLE:
            raise ValueError('User and Password must be specified')

        if (user and password):
            kwargs.update({
                'user': user,
                'password': password
            })

        if authentication == SASL:
            bind_user = None

            if user:
                bind_user = user + '@' + (domain or self.realm).upper()

            if password and GSSAPI_EXT_PASSWORD:
                bind_user = GSSAPI_EXT_PASSWORD((bind_user, password))

            kwargs.update({
                'user': bind_user,
                'sasl_credentials': (
                    ldap_server + '/' + self.realm,
                ),
                'sasl_mechanism': GSSAPI,
            })

        elif authentication == NTLM:
            if not (user and password):
                raise ADDumperException(
                    'Insufficient credentials for NTLM authentication')

            if not '\\' in user:
                if not domain:
                    domain = self.realm.lower()

                kwargs['user'] = domain + '\\' + user

        elif authentication == SIMPLE:
            if not (user and password):
                raise ADDumperException(
                    'Insufficient credentials for SIMPLE authentication')

        self._kwargs = kwargs
        self._connect()

    def _connect(self, timeout=None):
        kwargs = dict(self._kwargs)
        if timeout:
            kwargs['receive_timeout'] = timeout

        self.connection = Connection(self.server, **kwargs)
        if not self.connection.bind():
            self.connection = None
            raise ADDumperException('Bind error')

        self._i_am = self.connection.extend.standard.who_am_i()

    def _try_connect_multi(
        self, ldap_server, global_catalog=False, recv_timeout=60,
            domain=None, user=None, password=None, authentication=None):

        if authentication is not None:
            self._try_connect_exact(
                ldap_server, global_catalog, recv_timeout,
                domain, user, password, authentication
            )
            return

        for authentication in (SASL, NTLM, SIMPLE):
            try:
                self._try_connect_exact(
                    ldap_server, global_catalog, recv_timeout,
                    domain, user, password, authentication
                )
                return

            except (ValueError, LDAPUnknownAuthenticationMethodError,
                    ADDumperException, gssexceptions.GSSError) as e:
                pass

        raise ADDumperException('Bind error (all failed)')

    @property
    def ldap_server(self):
        return self._preferred_ldap_server

    @property
    def name_server(self):
        return self._preferred_name_server[4][0]

    def __init__(
        self, realm,
        ldap_server=None, global_catalog=False, recv_timeout=60,
            domain=None, user=None, password=None,
            authentication=None, root=None, interrupt=None, timeout=600):

        if realm is None:
            if ldap_server:
                realm = ldap_server.upper()
            else:
                _, realm = getfqdn().split('.', 1)

        self.realm = realm.upper()

        self._interrupt = interrupt or Event()
        self._ns_socket = None
        self._ldap_servers = []
        self._name_servers = []
        self._preferred_ldap_server = None
        self._preferred_name_server = None
        self._timeout = timeout

        if not ldap_server and self._preferred_ldap_server:
            ldap_server = self._preferred_ldap_server

        if ldap_server:
            self.server = Server(
                ldap_server,
                get_info=ALL,
                port=3268 if global_catalog else 389,
                allowed_referral_hosts=[
                    ('*', True)
                ]
            )

            self._try_connect_multi(
                ldap_server, global_catalog,
                domain, user, password, authentication
            )

            self._preferred_ldap_server = ldap_server
        else:
            self._autodiscovery(global_catalog)

            for ldap_server in self._ldap_servers:
                if self._interrupt.is_set():
                    break

                try:
                    self.server = Server(
                        ldap_server.address,
                        connect_timeout=5,
                        port=ldap_server.port,
                        get_info=ALL,
                        allowed_referral_hosts=[
                            ('*', True)
                        ]
                    )

                    self._try_connect_multi(
                        ldap_server.address, global_catalog, recv_timeout,
                        domain, user, password, authentication
                    )

                    self._preferred_ldap_server = ldap_server.address
                    break

                except (socket_error, LDAPSocketOpenError, LDAPSocketReceiveError):
                    continue

        if not self.server:
            raise ValueError('Unable to connect to LDAP servers')

        self.root = root

        if self.root is None:
            self.root = self.server.info.other['defaultNamingContext'][0]

    def interrupt(self):
        self._interrupt.set()

    def dump(self, on_data, on_completed, interrupt,
            filter=None, minimal=False, timeout=600):
        ctx = LDAPContext(self.server, self.connection, self.root)

        categories = None

        dump_requests = self.SIMPLE_DUMP_REQUESTS

        if isinstance(filter, (str, unicode)):
            if filter.startswith('('):
                dump_requests = {
                    'custom_' + md5(filter).hexdigest(): LDAPLargeRequest(filter)
                }
            else:
                categories = tuple(set(cat.strip() for cat in filter.split(',')))
                filter = None

                dump_requests = {
                    name: request for name, request in
                    self.SIMPLE_DUMP_REQUESTS.iteritems()
                    if name in categories
                }

        for name, request in dump_requests.iteritems():
            if interrupt.is_set():
                if on_completed:
                    on_completed()

                return

            _on_data = lambda data: on_data(
                name, as_tuple_deep({
                    k:v for k,v in record.iteritems()
                    if k not in ('raw_attributes', 'raw_dn', 'type')
                } for record in data if record['type'] == 'searchResEntry')
            )

            request(
                ctx, _on_data, None, interrupt,
                minimal=minimal,
                custom_filter=filter
            )

        if on_completed:
            on_completed()

    def childs(self):
        result = self.connection.search(
            self.root, '(objectClass=domain)',
            BASE,
            attributes=['subRefs'],
            size_limit=1,
        )

        if not result:
            return False, self.connection.last_error

        response = list(self.connection.response)
        if len(response) != 1:
            return True, None

        return True, (self._i_am, response[0]['dn'], tuple(
            response[0]['attributes']['subRefs']))

    def info(self):
        return as_tuple_deep({
            'bind': self._i_am,
            'root': self.server.info.other['defaultNamingContext'][0],
            'dns': self._preferred_name_server,
            'ldap': self._preferred_ldap_server,
            'dns_servers': self._name_servers,
            'ldap_servers': self._ldap_servers,
            'info': {
                k:getattr(self.server.info, k) for k in (
                    'alt_servers', 'naming_contexts',
                    'supported_controls', 'supported_extensions',
                    'supported_features', 'supported_ldap_versions',
                    'supported_sasl_mechanisms', 'vendor_name',
                    'vendor_version', 'schema_entry',
                    'other'
                )
            }
        })

    def search(self, filter, attributes, base,
            amount=5, timeout=30, root=None, as_json=False):

        if isinstance(attributes, (str, unicode)):
            attributes = attributes.strip()
            if attributes != '*':
                attributes = list(
                    attr.strip() for attr in set(
                        attributes.split(',')))

        controls = []

        if 'ntsecuritydescriptor' in tuple(attr.lower() for attr in attributes):
            controls.append(build_sd_control())

        result = self.connection.search(
            self.root, filter,
            BASE if base else SUBTREE,
            attributes=attributes,
            controls=controls,
            size_limit=amount,
            time_limit=timeout
        )

        if not result:
            return False, self.connection.last_error

        if as_json:
            return True, self.connection.response_to_json(indent=1)
        else:
            return True, as_tuple_deep({
                k:v for k,v in record.iteritems()
                if k not in ('raw_attributes', 'raw_dn', 'type')
            } for record in self.connection.response
            if record['type'] == 'searchResEntry'
        )


def _get_ctx(
    realm, ldap_server, global_catalog, recv_timeout,
        domain, user, password, root,
        interrupt=None):

    ctx = REALM_CACHE.get(realm, None)
    if ctx:
        return ctx

    if (user and password):
        logger.info(
            '(Realm: %s) Use preconfigured credentials: domain=%s user=%s',
            realm, domain, user
        )

        ctx = ADCtx(
            realm, ldap_server, global_catalog, recv_timeout,
            domain, user, password,
            root=root, interrupt=interrupt
        )
    else:

        try:
            logger.info('(Realm: %s) Use SSO', realm)

            ctx = ADCtx(
                realm, ldap_server, global_catalog, recv_timeout,
                root=root, interrupt=interrupt
            )

            REALM_CACHE[realm] = ctx
            logger.info('(Realm: %s) Use SSO - ok (%s)', realm, ctx)
            return ctx

        except (ValueError, ADDumperException,
                gssexceptions.GSSError, LDAPUnknownAuthenticationMethodError) as e:

            logger.warning('(Realm: %s) Use SSO failed: %s', realm, e)


        for cred in find_creds(schema='ldap', realm=realm, username=user):
            logger.info(
                '(Realm: %s) Try netcreds: domain=%s user=%s',
                realm, domain, user
            )

            domain = cred.domain or cred.realm
            if domain:
                domain = domain.lower()

            user = cred.username
            password = cred.password

            try:
                ctx = ADCtx(
                    realm, ldap_server, global_catalog, recv_timeout,
                    domain, user, password,
                    root=root, interrupt=interrupt
                )

                logger.info(
                    '(Realm: %s) Try netcreds: domain=%s user=%s: ok (%s)',
                    realm, domain, user, ctx
                )
            except (ValueError, ADDumperException,
                    gssexceptions.GSSError, LDAPUnknownAuthenticationMethodError) as e:

                logger.warning(
                    '(Realm: %s) Try netcreds: domain=%s user=%s failed: %s',
                    realm, domain, user, e
                )
                continue

        if not ctx:
            logger.warning('(Realm: %s) No creds found', realm)
            raise ADDumperException('Bind error (all possible creds failed)')

    REALM_CACHE[realm] = ctx
    return ctx


def _dump(
    interrupt,
    on_data, on_completed,
        realm, ldap_server, global_catalog, recv_timeout,
        filter, minimal,
        domain, user, password, root):

    try:
        ctx = _get_ctx(
            realm, ldap_server, global_catalog, recv_timeout,
            domain, user, password, root,
            interrupt
        )

        if on_data:
            on_data('dns', ctx.name_server)
            on_data('ldap', ctx.ldap_server)

        ctx.dump(
            on_data, on_completed,
            interrupt, filter, minimal
        )

    except Exception as e:
        if interrupt.is_set():
            on_data('error', 'Interrupted')
        else:
            import traceback
            on_data(
                'error', '{}: {}'.format(
                    e, traceback.format_exc()
                )
            )

    finally:
        on_completed()


def dump(on_data, on_completed,
    realm, ldap_server=None, global_catalog=False, recv_timeout=60,
        filter=None, minimal=False, domain=None, user=None,
        password=None, root=None):

    interrupt = Event()
    thread = Thread(
        target=_dump,
        args=(
            interrupt,
            on_data,
            on_completed,
            realm, ldap_server, global_catalog, recv_timeout,
            filter, minimal,
            domain, user, password, root
        )
    )
    thread.daemon = True
    thread.start()

    return interrupt.set


def search(
    realm, ldap_server, global_catalog, recv_timeout,
        domain, user, password, root,
        term, attributes, base,
        amount, timeout, as_ldiff):

    ctx = _get_ctx(
       realm, ldap_server, global_catalog, recv_timeout,
       domain, user, password, root
    )

    return ctx.search(
        term, attributes, base,
        amount, timeout,  as_ldiff
    )


def childs(
    realm, ldap_server, global_catalog, recv_timeout,
        domain, user, password, root):

    ctx = _get_ctx(
       realm, ldap_server, global_catalog, recv_timeout,
       domain, user, password, root
    )

    return ctx.childs()

def info(
    realm, ldap_server, global_catalog, recv_timeout,
        domain, user, password, root):

    ctx = _get_ctx(
       realm, ldap_server, global_catalog, recv_timeout,
       domain, user, password, root
    )

    return ctx.info()
