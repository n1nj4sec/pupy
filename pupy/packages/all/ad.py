# -*- coding: utf-8 -*-

# Stolen from ldapdomaindump

from ldap3 import (
    Server, Connection, SIMPLE, ALL, BASE,
    SASL, NTLM, ALL_ATTRIBUTES, GSSAPI, RESTARTABLE
)
from ldap3.core.exceptions import (
    LDAPKeyError, LDAPAttributeError, LDAPInvalidDnError,
    LDAPSocketOpenError, LDAPSocketReceiveError,
    LDAPUnknownAuthenticationMethodError,
    LDAPCommunicationError, LDAPMaximumRetriesError
)

from ldap3.utils.config import set_config_parameter
from ldap3.utils.ciDict import CaseInsensitiveDict
from ldap3.protocol.controls import build_control
from ldap3.strategy.restartable import RestartableStrategy

from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.type.univ import Sequence, Integer

from socket import (
    getfqdn, socket, getaddrinfo, gaierror,
    SOCK_DGRAM, SOCK_STREAM, AF_INET, AF_INET6
)

from socket import error as socket_error
from sys import exc_info
from os import environ

from datetime import datetime
from threading import Thread, Event
from time import time, clock, mktime
from inspect import isgenerator
from hashlib import md5

from gssapi import exceptions as gssexceptions

try:
    from gssapi import GSSAPI_EXT_PASSWORD
except ImportError:
    GSSAPI_EXT_PASSWORD = False

from netaddr import IPAddress

from network.lib.dnsinfo import dnsinfo
from network.lib.scan import scan

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


# Monkey-patch _add_exception_to_history to save original exception,
# not some derived shit

_orig_add_exception_to_history = RestartableStrategy._add_exception_to_history

def _add_exception_to_history(self, exc):
    # exc ignored here
    exc_type, exc_value, exc_trace = exc_info()

    # GSSAPI exceptions to be raised fast. Unlikely something will change
    if issubclass(exc_type, gssexceptions.GSSError):
        raise exc_type, exc_value, exc_trace

    if exc_type:
        _orig_add_exception_to_history(self, exc_type(*exc_value))
    else:
        _orig_add_exception_to_history(self, exc)

RestartableStrategy._add_exception_to_history = _add_exception_to_history

set_config_parameter('RESTARTABLE_TRIES', 5)

REALM_CACHE = {}
DISCOVERY_CACHE = {}

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


def build_sd_control(sdflags=0x05):
    sdcontrol = SdFlags()
    sdcontrol.setComponentByName('Flags', sdflags)
    return build_control('1.2.840.113556.1.4.801', True, sdcontrol)


class ADException(Exception):
    type = 'generic'
    default_message = 'unknown exception'
    childs = []

    __slots__ = ('message',)

    def __init__(self, description=None, replace=False):
        self.message = self.default_message
        if description:
            if replace:
                self.message += ': ' + description
            else:
                self.message += ': ' + description

        super(ADException, self).__init__(self.message)

    def __str__(self):
        return self.__class__.__name__ + ': ' + self.message


class NoContext(ADException):
    type = 'operations'
    default_message = 'Realm not bound'


class AutodiscoveryFailed(ADException):
    type = 'discovery'
    default_message = 'Autodiscovery failed'

    __slots__ = ()


class AutodiscoveryNotAvailable(AutodiscoveryFailed):
    default_message = 'Autodiscovery not available'

    __slots__ = ()


class AutodiscoveryNoDnsServersFound(AutodiscoveryFailed):
    default_message = 'Autodiscovery not available - no discoverable DNS servers'

    __slots__ = ()


class AuthenticationError(ADException):
    type = 'auth'
    default_message = 'Authentication failed'


class BindError(AuthenticationError):
    default_message = 'Bind failed'


class NoCredentials(AuthenticationError):
    default_message = 'No creds'


class BindErrorMulti(BindError):
    default_message = 'Authentications failed'

    def __init__(self, childs):
        super(BindErrorMulti, self).__init__()
        self.childs = tuple(childs)


class CredentialsError(BindError):
    default_message = 'Invalid credentials'


class CommunicationError(ADException):
    type = 'communication'
    default_message = 'Connection failed'


class CommunicationErrorDiscovered(CommunicationError):
    default_message = 'Connection to all discovered servers failed'

    def __init__(self, childs):
        super(CommunicationErrorDiscovered, self).__init__()
        if not childs:
            self.childs = tuple()
            return

        self.childs = tuple(
            (
                authentication, ldap_server, domain, user,
                getattr(e, 'type', e.__class__.__name__),
                e.message
            ) for authentication, ldap_server, domain, user, e in childs
        )


class CommunicationErrorNoDiscovered(CommunicationError):
    default_message = 'No servers found'


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
        'global_catalog',
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

    def _bootstrap_ns(self, timeout=1, first=True, on_data=None):
        query = dnslib.DNSRecord.question(self.realm, 'SOA')

        try:
            addrs = getaddrinfo(self.realm, 53)
        except gaierror:
            addrs = []
            logger.info('No DNS servers found for this realm')

        local_addrs, _ = dnsinfo()
        local_addrs = [
            (
                AF_INET6 if IPAddress(addr).version == 6 else AF_INET,
                SOCK_DGRAM,
                0,
                '',
                (addr, 53)
            ) for addr in local_addrs
        ]

        local_addrs.extend(addrs)

        # Also add local DNS

        for addr in local_addrs:
            if self._interrupt.is_set():
                break

            family, kind, proto, _, endpoint = addr
            logger.info('DNS: Try %s:%d', *endpoint)

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
                    logger.info(
                        'Bootstrap DNS: %s: SOA request failed', endpoint[0])
                    continue

                self._name_servers.append((addr, duration))
                if first:
                    return True

            except socket_error as e:
                logger.info('Bootstrap DNS %s: Socket error %s', endpoint[0], e)
                pass

            except Exception as e:
                logger.exception(e)

            finally:
                s.close()

        logger.info('Selected DNS: %s', self._name_servers)
        return bool(self._name_servers)

    def _select_fastest_ns(self, on_data=None):
        if not self._name_servers:
            for timeout in (1, 5):
                if self._bootstrap_ns(timeout=timeout, on_data=None):
                    break

        if not self._name_servers:
            if on_data:
                on_data('No accessible DNS found')

            raise AutodiscoveryNoDnsServersFound()

        self._preferred_name_server, duration = sorted(
            self._name_servers, key=lambda (_, duration): duration
        )[0]

        if on_data:
            on_data('Preferred DNS: {} (rt: {:02f}ms)'.format(
                self._preferred_name_server[4][0], duration * 1000))

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
                    self._ns_socket.settimeout(5)
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

            if not response:
                continue

            parsed = dnslib.DNSRecord.parse(response)
            if parsed.header.rcode != dnslib.RCODE.NOERROR:
                return []

            return [
                record.rdata for record in parsed.rr
                if dnslib.QTYPE[record.rtype] == qtype
            ]

    def _autodiscovery(self,
            global_catalog=False, on_data=None, interrupt=None):

        if not auto_discovery:
            raise AutodiscoveryNotAvailable()

        key = (self.realm, global_catalog)

        if key in DISCOVERY_CACHE:
            ts, _ldap_servers = DISCOVERY_CACHE[key]

            if time() - ts < 3600:
                self._ldap_servers = _ldap_servers
            else:
                del DISCOVERY_CACHE[key]

            if self._ldap_servers:
                return

        self._select_fastest_ns(on_data)

        if on_data:
            on_data(
                'Discovery {} servers for realm {} using DNS {}'.format(
                    'GC' if global_catalog else 'LDAP', self.realm,
                    self._preferred_name_server[4][0]))

        ldap_servers = self._resolve('_ldap._tcp.' + self.realm, 'SRV')
        if not ldap_servers:
            raise AutodiscoveryFailed()

        _ldap_servers = []

        for ldap_server in ldap_servers:
            record = ADLdapServer(
                ldap_server.target, ldap_server.port,
                ldap_server.priority
            )

            _ldap_servers.append(record)

        _ldap_servers = sorted(_ldap_servers)

        self._ldap_servers = []

        _gc_ldap_servers = []

        if global_catalog:
            gc_ldap_servers = self._resolve(
                '_ldap._tcp.gc._msdcs.' + self.realm, 'SRV')

            if gc_ldap_servers:
                for ldap_server in gc_ldap_servers:
                    record = ADLdapServer(
                        ldap_server.target, ldap_server.port,
                        ldap_server.priority
                    )

                    _gc_ldap_servers.append(record)

                _gc_ldap_servers = sorted(_gc_ldap_servers)

                # Global catalog has priority
                self._ldap_servers.extend(_gc_ldap_servers)

        self._ldap_servers.extend(_ldap_servers)

        hosts = set(server.address for server in self._ldap_servers)
        ports = set(server.port for server in self._ldap_servers)

        if on_data:
            on_data('Check connection ({} servers)'.format(len(
                self._ldap_servers)))

        connectables = scan(hosts, ports, interrupt)
        self._ldap_servers = [
            server for server in self._ldap_servers
            if (server.address, server.port) in connectables
        ]

        DISCOVERY_CACHE[key] = time(), self._ldap_servers

        if on_data:
            on_data(('Discovered', tuple(
                '{}:{}'.format(server.address, server.port)
                for server in self._ldap_servers)))

    def _try_connect_exact(
        self, server, ldap_server, global_catalog=False, recv_timeout=60,
            domain=None, user=None, password=None,
            authentication=None, sasl_princ_use_realm=True):

        kwargs = {
            'authentication': authentication,
            # Broken with SASL
            # 'auto_referrals': True,
            # 'use_referral_cache': True,
            'auto_referrals': False,
            'receive_timeout': self._timeout,
            'client_strategy': RESTARTABLE
        }

        if not (user and password) and authentication == SIMPLE:
            raise NoCredentials()

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

            sasl_ldap_server = ldap_server
            if sasl_princ_use_realm:
                sasl_ldap_server += '/' + self.realm

            kwargs.update({
                'user': bind_user,
                'sasl_credentials': (
                    ldap_server,
                ),
                'sasl_mechanism': GSSAPI,
            })

        elif authentication == NTLM:
            if not (user and password):
                raise NoCredentials()

            if '\\' not in user:
                if not domain:
                    domain = self.realm.lower()

                kwargs['user'] = domain + '\\' + user

        elif authentication == SIMPLE:
            if not (user and password):
                raise NoCredentials()

        self._kwargs = kwargs

        try:
            self._connect(server)
        except gssexceptions.GSSError as e:
            gssmaj, gssmin = e.args
            msgmaj, majcode = gssmaj
            msgmin, _ = gssmin
            if (majcode & 0xb0000 == 0xb0000) \
                and authentication == SASL and sasl_princ_use_realm:

                self._try_connect_exact(
                    server, ldap_server, global_catalog, recv_timeout,
                    domain, user, password,
                    authentication, False
                )
            elif majcode & 0xd0000 == 0xd0000:
                raise NoCredentials(
                    'GSSAPI: ' + msgmin, replace=True
                )
            else:
                raise NoCredentials(
                    'GSSAPI: ' + msgmaj + (
                        (': ' + msgmin) if msgmin != 'Success' else ''
                    ), replace=True
                )

        except Exception as e:
            logger.info(
                'LDAP Connect failed: server=%s args=%s: %s',
                ldap_server, kwargs, e
            )
            raise

    def _connect(self, server=None, timeout=None):
        kwargs = dict(self._kwargs)
        if timeout:
            kwargs['receive_timeout'] = timeout

        self.connection = Connection(
            server or self.server, **kwargs
        )

        if not self.connection.bind():
            last_error = self.connection.last_error
            self.connection = None
            raise BindError(last_error)

        self._i_am = self.connection.extend.standard.who_am_i()
        self.server = server

    def _try_connect_multi(
        self, server, ldap_server, global_catalog=False, recv_timeout=60,
            domain=None, user=None, password=None, authentication=None):

        errors = []

        if authentication is not None:
            self._try_connect_exact(
                server,
                ldap_server, global_catalog, recv_timeout,
                domain, user, password, authentication
            )
            return

        for authentication in (SASL, NTLM, SIMPLE):
            try:
                self._try_connect_exact(
                    server,
                    ldap_server, global_catalog, recv_timeout,
                    domain, user, password, authentication
                )

                logger.info(
                    'Authenticated to %s with %s',
                    ldap_server, authentication
                )
                return

            except AuthenticationError as e:
                errors.append(
                    (authentication, ldap_server, domain, user, e)
                )

        raise BindErrorMulti(errors)

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
            authentication=None, root=None, interrupt=None, timeout=600,
            on_data=None):

        if not realm:
            raise ValueError('Realm can not be empty')

        self.realm = realm.upper()
        self.global_catalog = global_catalog
        self.server = None

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
            server = Server(
                ldap_server,
                get_info=ALL,
                port=3268 if global_catalog else 389,
                # Broken in ldap3 (SASL issues)
                # allowed_referral_hosts=[
                #     ('*', True)
                # ]
            )

            if on_data:
                on_data('Connecting to {}'.format(ldap_server))

            self._try_connect_multi(
                server,
                ldap_server, global_catalog,
                domain, user, password, authentication
            )

            self._preferred_ldap_server = ldap_server
        else:
            try:
                self._autodiscovery(global_catalog, on_data, interrupt)
            except AutodiscoveryFailed as e:
                if on_data:
                    on_data(
                        'Autodiscovery failed, try {} as LDAP'.format(
                            realm))

                logger.info(
                    'Autodiscovery failed: %s. Try realm as LDAP',
                    e.message
                )

                self._ldap_servers = [
                    ADLdapServer(realm, 389, 0)
                ]

            errors = []
            known_invalid_creds = []

            for multi_ldap_server in self._ldap_servers:
                if self._interrupt.is_set():
                    break

                if (domain, user, password, authentication) in known_invalid_creds:
                    logger.info(
                        'Omit %s: no creds for method %s', multi_ldap_server.address,
                        authentication
                    )
                    continue

                try:
                    server = Server(
                        multi_ldap_server.address,
                        connect_timeout=5,
                        port=multi_ldap_server.port,
                        get_info=ALL,
                        allowed_referral_hosts=[
                            ('*', True)
                        ]
                    )

                    if on_data:
                        on_data('[Try] Connecting to {}'.format(
                            multi_ldap_server.address))

                    self._try_connect_multi(
                        server,
                        multi_ldap_server.address, global_catalog, recv_timeout,
                        domain, user, password, authentication
                    )

                    self._preferred_ldap_server = multi_ldap_server.address
                    break

                except gaierror as e:
                    logger.info(
                        'Can not resolve %s: %s, try next if any',
                        multi_ldap_server.address,
                        e
                    )
                    errors.append(
                        CommunicationError(str(e))
                    )

                except BindErrorMulti as e:
                    errors.extend(e.childs)
                    for (authentication, ldap_server, domain, user, exc) in e.childs:
                        if isinstance(exc, NoCredentials):
                            known_invalid_creds.append(
                                (domain, user, password, authentication)
                            )

                except (
                    socket_error, LDAPSocketOpenError, LDAPSocketReceiveError,
                    LDAPCommunicationError, LDAPMaximumRetriesError) as e:
                    errors.append((domain, user, password, authentication, e))
                    continue

        if not self.server:
            if errors:
                raise BindErrorMulti(errors)
            else:
                raise CommunicationErrorNoDiscovered()

        self.root = root

        if self.root is None and self.server.info and self.server.info.other:
            if 'defaultNamingContext' in self.server.info.other:
                self.root = self.server.info.other['defaultNamingContext'][0]
            else:
                self.root = next(iter(self.server.info.naming_contexts))

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
        try:
            result = self.connection.search(
                self.root, '(objectClass=domain)',
                BASE,
                attributes=['subRefs'],
                size_limit=1,
            )
        except LDAPAttributeError:
            return False, "Not supported"

        if not result:
            return False, self.connection.last_error

        response = list(self.connection.response)
        if len(response) != 1:
            return True, None

        return True, (self._i_am, response[0]['dn'], tuple(
            response[0]['attributes']['subRefs']))

    def info(self):
        info = {
            'bind': self._i_am,
            'root': self.root or '',
            'dns': self._preferred_name_server,
            'ldap': self._preferred_ldap_server,
            'dns_servers': self._name_servers,
            'ldap_servers': self._ldap_servers
        }

        info['info'] = {
            k:getattr(self.server.info, k) for k in (
                'alt_servers', 'naming_contexts',
                'supported_controls', 'supported_extensions',
                'supported_features', 'supported_ldap_versions',
                'supported_sasl_mechanisms', 'vendor_name',
                'vendor_version', 'schema_entry',
                'other'
            )
        }

        return as_tuple_deep(info)

    def search(self, filter, attributes, base, root,
            amount=5, timeout=30, as_json=False):

        controls = []

        if 'ntsecuritydescriptor' in tuple(attr.lower() for attr in attributes):
            controls.append(build_sd_control())

        try:
            result = self.connection.search(
                root or self.root, filter, base,
                attributes=attributes,
                controls=controls,
                size_limit=amount,
                time_limit=timeout
            )
        except (LDAPAttributeError, LDAPInvalidDnError) as e:
            return False, str(e)

        if not result:
            if not self.connection.last_error:
                return True, []

            return False, self.connection.last_error

        if as_json:
            return True, self.connection.response_to_json(indent=1)
        else:
            result = []
            for record in self.connection.response:
                if record['type'] != 'searchResEntry':
                    continue

                item = record['attributes']
                if 'distinguishedName' in item:
                    del item['distinguishedName']

                item['dn'] = record['dn']
                result.append(item)

            return True, result


def _get_realm(realm, on_data=None):
    if not realm:
        if len(REALM_CACHE) == 1:
            realm = REALM_CACHE[next(iter(REALM_CACHE))].realm
            if on_data:
                on_data('[Resue] Realm: {}'.format(realm))
        else:
            realm = environ.get('USERDNSDOMAIN', None)
            if realm:
                if on_data:
                    on_data('[env] Realm: {}'.format(realm))
            else:
                fqdn = getfqdn()
                if '.' in fqdn:
                    _, realm = fqdn.split('.', 1)
                    if on_data:
                        on_data('[fqdn] Realm: {}'.format(realm))
                else:
                    _, domains = dnsinfo()
                    if not domains:
                        raise AutodiscoveryFailed('No way to find default realm')
                    else:
                        realm = domains[0]
                        if on_data:
                            on_data('[dnsinfo] Realm: {}'.format(realm))

    return str(realm).strip().upper()


def _get_cached_ctx(realm, global_catalog=False, on_data=None):
    realm = _get_realm(realm, on_data)
    key = (
        ('GC' if global_catalog else 'LDAP'),
        realm
    )

    return key, realm, REALM_CACHE.get(key, None)


def _get_ctx(
    interrupt, on_data,
    realm, ldap_server, global_catalog, recv_timeout,
        domain, user, password, root):

    key, realm, ctx = _get_cached_ctx(realm, global_catalog, on_data)
    if ctx:
        return ctx

    if (user and password):
        logger.info(
            '(Realm: %s) Use preconfigured credentials: domain=%s user=%s',
            realm, domain, user
        )

        on_data('[auth] Realm: {} - user: {}\\{}'.format(realm, domain, user))
        ctx = ADCtx(
            realm, ldap_server, global_catalog, recv_timeout,
            domain, user, password,
            root=root, interrupt=interrupt, on_data=on_data
        )
    else:
        errors = []

        try:
            logger.info('(Realm: %s) Use SSO', realm)
            if on_data:
                on_data('[auth] Realm: {} - try SSO'.format(realm))

            ctx = ADCtx(
                realm, ldap_server, global_catalog, recv_timeout,
                root=root, interrupt=interrupt, on_data=on_data
            )

            REALM_CACHE[key] = ctx
            logger.info('(Realm: %s) Use SSO - ok (%s)', realm, ctx)
            return ctx

        except BindErrorMulti as e:
            errors.extend(e.childs)

        except (
            ADException, gssexceptions.GSSError,
                LDAPUnknownAuthenticationMethodError, LDAPMaximumRetriesError) as e:

            logger.warning('(Realm: %s) Use SSO failed: %s', realm, e)

        for cred in find_creds(schema='ldap', realm=realm.lower(), username=user):
            if interrupt.is_set():
                break

            domain = cred.domain or cred.realm
            user = cred.username
            password = cred.password

            if not user:
                # We already tried SSO
                continue

            if on_data:
                on_data('[Try] Credentials {}\\{}'.format(
                    domain, user))

            logger.info(
                '(Realm: %s) Try netcreds: domain=%s user=%s',
                realm, domain, user
            )

            try:
                ctx = ADCtx(
                    realm, ldap_server, global_catalog, recv_timeout,
                    domain, user, password,
                    root=root, interrupt=interrupt, on_data=on_data
                )

                logger.info(
                    '(Realm: %s) Try netcreds: domain=%s user=%s: ok (%s)',
                    realm, domain, user, ctx
                )

            except BindErrorMulti as e:
                errors.extend(e.childs)

            except (ValueError, ADException,
                    gssexceptions.GSSError, LDAPUnknownAuthenticationMethodError) as e:

                logger.warning(
                    '(Realm: %s) Try netcreds: domain=%s user=%s failed: %s',
                    realm, domain, user, e
                )
                continue

        if not ctx:
            logger.warning('(Realm: %s) No creds found', realm)
            raise CommunicationErrorDiscovered(errors)

    REALM_CACHE[key] = ctx
    return ctx


def _dump(ctx, interrupt, on_data, on_completed, filter, minimal):
    try:
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


def _bind(
    interrupt, on_data, on_completed,
    realm, global_catalog, ldap_server=None, recv_timeout=60,
    domain=None, user=None, password=None, root=None
):
    bound_to = None

    if on_data:
        if global_catalog:
            on_data(
                'Bind to ' + (
                    'Global Catalog' if global_catalog else 'LDAP'))

    try:
        ctx = _get_ctx(
            interrupt, on_data,
            realm, ldap_server, global_catalog, recv_timeout,
            domain, user, password, root
        )

        bound_to = ctx.ldap_server

        if on_completed:
            on_completed(True, bound_to)

    except Exception as e:
        logger.exception(e)

        if on_completed:
            on_completed(False, str(e))
        else:
            raise


def bind(
    on_data, on_completed,
    realm, global_catalog, ldap_server=None, recv_timeout=60,
    domain=None, user=None, password=None, root=None
):
    interrupt = Event()
    thread = Thread(
        target=_bind,
        args=(
            interrupt, on_data, on_completed,
            realm, global_catalog, ldap_server, recv_timeout,
            domain, user, password, root
        )
    )
    thread.daemon = True
    thread.start()

    return interrupt.set


def unbind(realm, global_catalog=False):
    key, _, ctx =_get_cached_ctx(realm, global_catalog)
    if not ctx:
        raise NoContext()

    try:
        ctx.connection.unbind()
    finally:
        del REALM_CACHE[key]


def dump(on_data, on_completed, realm, global_catalog=False,
        filter=None, minimal=False):
    key, _, ctx =_get_cached_ctx(realm, global_catalog)
    if not ctx:
        raise NoContext()

    interrupt = Event()
    thread = Thread(
        target=_dump,
        args=(
            ctx, interrupt, on_data, on_completed,
            filter, minimal
        )
    )
    thread.daemon = True
    thread.start()

    return interrupt.set


def search(realm, global_catalog, term,
        attributes, base, root, amount, timeout, as_ldiff):
    ctxs = []
    if realm:
        key, _, ctx =_get_cached_ctx(realm, global_catalog)
        if not ctx:
            raise NoContext()

        ctxs.append(ctx)
    elif global_catalog is not None:
        expected_btype = 'GC' if global_catalog else 'LDAP'
        ctxs.extend([
            ctx for (btype, _), ctx in REALM_CACHE.iteritems()
            if btype == expected_btype
        ])
    else:
        ctx.extend(REALM_CACHE.values())

    if not ctxs:
        raise NoContext('any')

    if len(ctxs) > 1:
        results = {}
    else:
        results = []

    errors = []
    ok = False

    for ctx in ctxs:
        try:
            success, result = ctx.search(
                term, attributes, base, root,
                amount, timeout, as_ldiff
            )
        except Exception:
            success = False
            import traceback
            result = traceback.format_exc()

        if success:
            if len(ctxs) > 1:
                key = (
                    'GC ' if ctx.global_catalog else ''
                ) + ctx.realm
                results[key] = result
            else:
                results.extend(result)

            ok = True
        else:
            result = ctx.realm + ': ' + result
            errors.append(result)

    if not ok:
        return False, '\n'.join(errors)

    return ok, as_tuple_deep(results)


def childs(realm, global_catalog):
    key, _, ctx =_get_cached_ctx(realm, global_catalog)
    if not ctx:
        raise NoContext()

    return ctx.childs()


def info(realm, global_catalog):
    key, _, ctx =_get_cached_ctx(realm, global_catalog)
    if not ctx:
        raise NoContext()

    return ctx.info()


def bounded():
    return tuple(REALM_CACHE.keys())
