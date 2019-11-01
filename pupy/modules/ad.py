# -*- coding: utf-8 -*-

from ldap3.protocol.formatters.formatters import format_sid
from impacket.ldap.ldaptypes import (
    SR_SECURITY_DESCRIPTOR, ACCESS_MASK
)

from pupylib.PupyConfig import PupyConfig
from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Pygment, List, Table, MultiPart

from pygments import lexers

from os.path import basename
from json import dumps
from io import open as io_open

from threading import Event
from datetime import datetime
from uuid import UUID


__class_name__ = 'AD'

IMM = 0
LIST = 1
MAP = 2
DATE = 3

# search attributes
ALL_ATTRIBUTES = '*'
NO_ATTRIBUTES = '1.1'  # as per RFC 4511
ALL_OPERATIONAL_ATTRIBUTES = '+'  # as per RFC 3673

# search scope
BASE = 'BASE'
LEVEL = 'LEVEL'
SUBTREE = 'SUBTREE'

# User account control flags
# From: https://blogs.technet.microsoft.com/askpfeplat/2014/01/15/understanding-the-useraccountcontrol-attribute-in-active-directory/
uac_flags = {
    'ACCOUNT_DISABLED':0x00000002,
    'ACCOUNT_LOCKED':0x00000010,
    'PASSWD_NOTREQD':0x00000020,
    'PASSWD_CANT_CHANGE': 0x00000040,
    'NORMAL_ACCOUNT': 0x00000200,
    'WORKSTATION_ACCOUNT':0x00001000,
    'SERVER_TRUST_ACCOUNT': 0x00002000,
    'DONT_EXPIRE_PASSWD': 0x00010000,
    'SMARTCARD_REQUIRED': 0x00040000,
    'TRUSTED_FOR_DELEGATION': 0x00080000,
    'NOT_DELEGATED': 0x00100000,
    'USE_DES_KEY_ONLY': 0x00200000,
    'DONT_REQ_PREAUTH': 0x00400000,
    'PASSWORD_EXPIRED': 0x00800000,
    'TRUSTED_TO_AUTH_FOR_DELEGATION': 0x01000000,
    'PARTIAL_SECRETS_ACCOUNT': 0x04000000
}

# https://docs.microsoft.com/en-us/windows/win32/adschema/a-samaccounttype
sam_flags = {
    'SAM_DOMAIN_OBJECT': 0x0,
    'SAM_GROUP_OBJECT': 0x10000000,
    'SAM_NON_SECURITY_GROUP_OBJECT': 0x10000001,
    'SAM_ALIAS_OBJECT': 0x20000000,
    'SAM_NON_SECURITY_ALIAS_OBJECT': 0x20000001,
    'SAM_NORMAL_USER_ACCOUNT': 0x30000000,
    'SAM_MACHINE_ACCOUNT': 0x30000001,
    'SAM_TRUST_ACCOUNT': 0x30000002,
    'SAM_APP_BASIC_GROUP': 0x40000000,
    'SAM_APP_QUERY_GROUP': 0x40000001,
    'SAM_ACCOUNT_TYPE_MAX': 0x7fffffff
}

# Password policy flags
pwd_flags = {
    'PASSWORD_COMPLEX':0x01,
    'PASSWORD_NO_ANON_CHANGE': 0x02,
    'PASSWORD_NO_CLEAR_CHANGE': 0x04,
    'LOCKOUT_ADMINS': 0x08,
    'PASSWORD_STORE_CLEARTEXT': 0x10,
    'REFUSE_PASSWORD_CHANGE': 0x20
}

# Domain trust flags
# From: https://msdn.microsoft.com/en-us/library/cc223779.aspx
trust_flags = {
    'NON_TRANSITIVE':0x00000001,
    'UPLEVEL_ONLY':0x00000002,
    'QUARANTINED_DOMAIN':0x00000004,
    'FOREST_TRANSITIVE':0x00000008,
    'CROSS_ORGANIZATION':0x00000010,
    'WITHIN_FOREST':0x00000020,
    'TREAT_AS_EXTERNAL':0x00000040,
    'USES_RC4_ENCRYPTION':0x00000080,
    'CROSS_ORGANIZATION_NO_TGT_DELEGATION':0x00000200,
    'PIM_TRUST':0x00000400
}

# Domain trust direction
# From: https://msdn.microsoft.com/en-us/library/cc223768.aspx
trust_directions = {
    'INBOUND':0x01,
    'OUTBOUND':0x02,
    'BIDIRECTIONAL':0x03
}

# Domain trust types
trust_type = {
    'DOWNLEVEL':0x01,
    'UPLEVEL':0x02,
    'MIT':0x03
}

# Common attribute pretty translations
attr_translations = {
    'sAMAccountName':'SAM Name',
    'cn':'CN',
    'operatingSystem':'Operating System',
    'operatingSystemServicePack':'Service Pack',
    'operatingSystemVersion':'OS Version',
    'userAccountControl':'Flags',
    'objectSid':'SID',
    'memberOf':'Member of groups',
    'primaryGroupId':'Primary group',
    'dNSHostName':'DNS Hostname',
    'whenCreated':'Created on',
    'whenChanged':'Changed on',
    'IPv4':'IPv4 Address',
    'lockOutObservationWindow':'Lockout time window',
    'lockoutDuration':'Lockout Duration',
    'lockoutThreshold':'Lockout Threshold',
    'maxPwdAge':'Max password age',
    'minPwdAge':'Min password age',
    'minPwdLength':'Min password length',
    'pwdHistoryLength':'Password history length',
    'pwdProperties':'Password properties',
    'ms-DS-MachineAccountQuota':'Machine Account Quota',
    'flatName':'NETBIOS Domain name'
}

sid_translations = {
    'S-1-0-0': 'NULL',
    'S-1-1-0': 'EVERYONE',
    'S-1-2-0': 'LOCAL',
    'S-1-2-1': 'CONSOLE',
    'S-1-3-0': 'OWNER',
    'S-1-3-1': 'OWNER GROUP',
    'S-1-3-2': 'OWNER SERVER',
    'S-1-3-3': 'OWNER SERVER GROUP',
    'S-1-3-4': 'OWNER RIGHTS',
    'S-1-4': 'AUTHORITY',
    'S-1-5': 'NT AUTHORITY',
    'S-1-5-18': 'Local System',
    'S-1-5-19': 'Local Service',
    'S-1-5-20': 'Network Service',
    'S-1-5-80': 'All services',
    'S-1-5-18': 'Local Admin',
    'S-1-5-32-544': r'BUILTIN\Administrators',
    'S-1-5-32-546': 'GUESTS'
}


def json_default(o):
    if isinstance(o, datetime):
        return o.isoformat()


#Convert password max age (in 100 nanoseconds), to days
def nsToDays(length):
    return abs(length) * .0000001 / 86400


def nsToMinutes(length):
    return abs(length) * .0000001 / 60


def toDateTime(filetime):
    if isinstance(filetime, datetime):
        return filetime

    if not filetime:
        return datetime.utcfromtimestamp(0)

    return datetime.utcfromtimestamp(float(
        (filetime / 10000000) - 11644473600))


#Parse bitwise flags into a list
def parseFlags(attr, flags_def, bits=True):
    if not attr:
        return tuple()

    if not isinstance(attr, int):
        attr = int(attr)

    return tuple(
        flag for flag, val in flags_def.iteritems()
        if (bits and (attr & val == val)) or (
            not bits and attr == val
        )
    )


def LDAPAclMaskToSet(mask):
    flags = (
        'GENERIC_READ', 'GENERIC_WRITE', 'GENERIC_EXECUTE',
        'GENERIC_ALL', 'MAXIMUM_ALLOWED', 'ACCESS_SYSTEM_SECURITY',
        'SYNCHRONIZE', 'WRITE_OWNER', 'WRITE_DACL', 'READ_CONTROL',
        'DELETE'
    )

    result = []

    for flag in flags:
        value = getattr(ACCESS_MASK, flag)
        if mask['Mask'] & value == value:
            result.append(flag)

    return result


def LDAPAclToDict(acl):
    if not acl:
        return None

    result = []
    for ace in acl.aces:
        sid = ace['Ace']['Sid'].formatCanonical()
        result.append({
            'Type': ace['TypeName'][:-4],
            'Sid': sid_translations.get(sid, sid),
            'Mask': LDAPAclMaskToSet(ace['Ace']['Mask'])
        })

    return result


def LDAPAclOwnerToDict(owner):
    if not owner:
        return None

    sid = owner.formatCanonical()
    return sid_translations.get(sid, sid)


def LDAPSdToDict(descriptor):
    if not descriptor:
        return None

    return {
        'Owner': LDAPAclOwnerToDict(descriptor['OwnerSid']),
        'Group': LDAPAclOwnerToDict(descriptor['GroupSid']),
        'SACL': LDAPAclToDict(descriptor['Sacl']),
        'DACL': LDAPAclToDict(descriptor['Dacl'])
    }


def formatAttribute(key, att, formatCnAsGroup=False):
    aname = key.lower()

    if isinstance(att, tuple) and len(att) == 1:
        att = att[0]
        if isinstance(att, (str, unicode)):
            att = att.strip()
            try:
                att = int(att)
            except ValueError:
                try:
                    att = float(att)
                except ValueError:
                    pass

    if aname == 'useraccountcontrol':
        return parseFlags(att, uac_flags)

    #Pwd flags
    elif aname == 'pwdproperties':
        return parseFlags(att, pwd_flags)

    #Sam flags
    elif aname == 'samaccounttype':
        return parseFlags(att, sam_flags, False)

    #Domain trust flags
    elif aname == 'trustattributes':
        return parseFlags(att, trust_flags)

    elif aname == 'trustdirection':
        if  att == 0:
            return 'DISABLED'
        else:
            return parseFlags(att, trust_directions, False)

    elif aname == 'trusttype':
        return parseFlags(att, trust_type)

    elif aname in (
            'securityidentifier', 'objectsid') and att.startswith('hex:'):
        sid = format_sid(att[4:].decode('hex'))
        return sid_translations.get(sid, sid)

    elif aname == 'minpwdage' or aname == 'maxpwdage':
        return '%.2f days' % nsToDays(att)

    elif aname == 'lockoutobservationwindow' or aname == 'lockoutduration':
        return '%.1f minutes' % nsToMinutes(att)

    elif aname == 'objectguid' and att.startswith('hex:'):
        return '{' + str(UUID(att[4:])) + '}'

    elif aname in (
        'pwdlastchange', 'badpasswordtime', 'lastlogon',
            'lastlogontimestamp', 'lockouttime'):
        return toDateTime(att)

    elif aname in ('ntsecuritydescriptor',):
        if att.startswith('hex:'):
            att = att[4:].decode('hex')
        srsd = SR_SECURITY_DESCRIPTOR()
        srsd.fromString(att)
        return LDAPSdToDict(srsd)

    return att


def from_tuple_deep(obj, format=True):
    kind, data = obj
    if kind == IMM:
        if isinstance(data, str):
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                return 'hex:' + data.encode('hex')

        return data

    elif kind == LIST:
        return tuple(
            from_tuple_deep(item) for item in data
        )

    elif kind == MAP and format:
        return {
            k: formatAttribute(k, from_tuple_deep(v)) for (k, v) in data
        }

    elif kind == MAP and not format:
        return {
            k: from_tuple_deep(v) for (k, v) in data
        }

    elif kind == DATE:
        return datetime.utcfromtimestamp(data)

    else:
        raise ValueError('Invalid kind ({})'.format(kind))


@config(cat='admin')
class AD(PupyModule):
    ''' Dump information from Active Directory '''

    dependencies = {
        'all': ['gssapi', 'ldap3'],
        'posix': ['kerberos'],
        'windows': ['winkerberos']
    }

    terminate = None

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='ad', description=cls.__doc__)
        cls.arg_parser.add_argument(
            '-r', '--realm', help='Realm to work with'
        )

        commands = cls.arg_parser.add_subparsers(title='commands')

        bind = commands.add_parser('bind', help='Bind to server')
        bind.add_argument('-l', '--ldap-server', help='DNS address of LDAP server')
        bind.add_argument(
            '-G', '--global-catalog', default=False, action='store_true',
            help='Use AD Global catalg')
        bind.add_argument('-T', '--recv-timeout', default=60, help='Socket read timeout')
        bind.add_argument('-u', '--username', help='Username to authenticate')
        bind.add_argument('-p', '--password', help='Password to authenticate')
        bind.add_argument('-d', '--domain', help='Domain for Username')
        bind.add_argument('-r', '--root', help='LDAP root')
        bind.set_defaults(func=cls.bind)

        unbind = commands.add_parser('unbind', help='Disconnect and forget realm')
        unbind.set_defaults(func=cls.unbind)

        bounded = commands.add_parser('list', help='Show bounded realms')
        bounded.set_defaults(func=cls.bounded)

        info = commands.add_parser('info', help='Info about current AD context')
        info.set_defaults(func=cls.getinfo)

        dump = commands.add_parser('dump', help='Dump results of large searches')
        dump.add_argument('-f', '--filter', help='LDAP custom filter')
        dump.add_argument(
            '-F', '--full', default=False,
            action='store_true', help='Dump all attributes')
        dump.add_argument(
            'target', nargs='?',
            help='Categories to dump, i.e.: users,computers OR '
            'filter like (&(attr=XYZ)(attr2=CCC))'
        )
        dump.set_defaults(func=cls.dump)

        childs = commands.add_parser('childs', help='Related AD servers')
        childs.set_defaults(func=cls.childs)

        search = commands.add_parser(
            'search',
            help='Search in AD (only small and fast, for large use dump)'
        )
        search.add_argument(
            '-T', '--table', action='store_true', default=False,
            help='Output as table'
        )
        search.add_argument(
            'term', help='Search filter',
            default='(objectClass=domain)',
        )
        search.add_argument(
            'attributes', nargs='?', default=NO_ATTRIBUTES,
            help='Attributes to search (Use * for ALL, default none)'
        )

        level = search.add_mutually_exclusive_group()
        level.add_argument(
            '-B', '--base', default=False, action='store_true',
            help='Use base search instead of subtree search. Default: False'
        )
        level.add_argument(
            '-L', '--level', default=False, action='store_true',
            help='Use level search instead of subtree search. Default: False'
        )

        search.add_argument(
            '-r', '--root', help='Use root instead of autodiscovered one'
        )
        search.add_argument(
            '-n', '--amount', default=5, type=int,
            help='Amount of records. Default: 5'
        )
        search.add_argument(
            '-t', '--timeout', default=5, type=int,
            help='Timeout (seconds). Default: 5'
        )
        search.set_defaults(func=cls.search)

    def _show_exception(self, e):
        if hasattr(e, 'message') and hasattr(e, 'type'):
            report = []
            if hasattr(e, 'childs') and e.childs and not isinstance(e.childs, str):
                for (authentication, ldap_server,
                        domain, user, _, emessage) in e.childs:
                    report.append({
                        'Method': authentication,
                        'Server': ldap_server,
                        'Domain': domain,
                        'User': user,
                        'Message': emessage
                    })

                self.error(
                    Table(report, [
                        'Method', 'Server', 'Domain', 'User', 'Message'
                    ], caption=e.message)
                )
            else:
                self.error('AD Error ({}): {}'.format(
                    e.type, e.message))
        else:
            self.error(e)

    def run(self, args):
        try:
            if args.realm == '.':
                args.realm = None

            args.func(self, args)
        except Exception as e:
            self._show_exception(e)

    def search(self, args):
        search = self.client.remote('ad', 'search')

        level = SUBTREE
        if args.base:
            level = BASE
        elif args.level:
            level = LEVEL

        need_attrs = []

        attributes = args.attributes
        fields = []

        if args.attributes in (ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES):
            pass
        elif args.attributes == NO_ATTRIBUTES:
            fields.append('dn')
        else:
            attributes = [
                attribute.strip() for attribute in args.attributes.split(',')
            ]

            for attribute in attributes:
                fields.append(attribute)

                if attribute.lower() == 'dn':
                    continue

                need_dn = False
                need_attrs.append(attribute)

            attributes = tuple(need_attrs)

        ok, result = search(
            args.realm,
            args.term, attributes,
            level, args.root,
            args.amount, args.timeout,
            False
        )

        if not ok:
            self.error(result)
            return

        results = from_tuple_deep(result, True)
        if len(fields) == 1:
            self.log(
                List(line[fields[0]] for line in results)
            )

        else:
            if args.table:
                self.log(
                    Table(results, fields or None)
                )
            else:
                filtered = results
                if fields:
                    filtered = [
                        {
                            field: result[field] for field in fields
                        } for result in results
                    ]

                formatted_json = dumps(
                    filtered,
                    indent=2, sort_keys=True,
                    default=json_default,
                    ensure_ascii=False
                )

                self.log(
                    Pygment(lexers.JsonLexer(), formatted_json)
                )

    def unbind(self, args):
        unbind = self.client.remote('ad', 'unbind')
        unbind(args.realm)

    def childs(self, args):
        childs = self.client.remote('ad', 'childs')
        ok, result = childs(args.realm)

        if not ok:
            self.error(result)
            return

        i_am, rootdn, childs = result

        self.log(List(childs, caption='Root: {} Whoami: {}'.format(rootdn, i_am)))

    def bounded(self, args):
        bounded = self.client.remote('ad', 'bounded')
        self.log(List(bounded()))

    def getinfo(self, args):
        info = self.client.remote('ad', 'info')
        desc = from_tuple_deep(info(args.realm), False)
        idesc = desc.get('info', {})

        infos = []

        versions = idesc.get(
            'supported_ldap_versions', []
        )

        if not hasattr(versions, '__iter__'):
            versions = [versions]

        infos.append(
            List([
                'Bind: ' + desc.get('bind', ''),
                'Root: ' + desc.get('root', ''),
                'LDAP: ' + desc.get('ldap', ''),
                'DNS: ' + desc['dns'][4][0] if desc.get('dns', None) else '',
                'Schema: ' + idesc.get('schema_entry', ''),
                'Versions: ' + ', '.join(str(version) for version in versions),
                'SASL Mechs: ' + ', '.join(
                    mech for mech in idesc.get(
                        'supported_sasl_mechanisms', []
                    )
                )
            ], caption='Connection')
        )

        if desc['ldap_servers']:
            infos.append(
                Table(
                    desc['ldap_servers'],
                    ['address', 'port', 'priority'],
                    caption='LDAP Servers'
                )
            )

        if desc['dns_servers']:
            infos.append(
                Table([
                    {
                        'IP': dns[0][4][0] + (
                            '/tcp' if dns[0][2] == 2 else '/udp'
                        ),
                        'Delay': '{:.02f}ms'.format(dns[1] * 1000),
                    } for dns in desc['dns_servers']
                ], ['IP', 'Delay'], caption='DNS Servers')
            )

        if not idesc:
            self.log(MultiPart(infos))
            return

        if idesc['alt_servers']:
            infos.append(
                List(idesc['alt_servers'], caption='Alternate servers')
            )

        if idesc['naming_contexts'] and not isinstance(
                idesc['naming_contexts'], (str, unicode)):
            infos.append(
                List(
                    idesc['naming_contexts'],
                    caption='Naming contexts'
                )
            )

        supported = []
        for table in ('supported_controls',
                'supported_extensions', 'supported_features'):
            for oid, klass, name, vendor in idesc[table]:
                supported.append({
                    'OID': oid,
                    'Type': klass,
                    'Name': name,
                    'Vendor': vendor
                })

        if supported:
            infos.append(
                Table(
                    supported, [
                        'OID', 'Type', 'Name', 'Vendor'
                    ],
                    caption='Supported features and extensions'
                )
            )

        if 'other' in idesc:
            infos.append(
                List(tuple(
                    '{}: {}'.format(key, value)
                    for key, value in idesc['other'].iteritems()
                    if key not in ('supportedLDAPPolicies',)
                ),
                caption='Other info')
            )

        self.log(MultiPart(infos))

    def dump(self, args):
        addump = self.client.remote('ad', 'dump', False)
        config = self.client.pupsrv.config or PupyConfig()

        context = {
            'last_name': None,
            'last_fobj': None,
        }

        completion = Event()

        def on_data(name, payload):
            if name == 'dns':
                self.success('DNS server selected: {}'.format(payload))
            elif name == 'ldap':
                self.success('LDAP server selected: {}'.format(payload))
            elif name == 'error':
                self.error('Error: {}'.format(payload))
            else:
                is_first = False

                if context['last_name'] != name:
                    is_first = True

                    if context['last_name']:
                        self.success('Completed {}'.format(context['last_name']))

                    dest = config.get_file(
                        'ad', {
                            r'%c': self.client.short_name(),
                            r'%n': basename(name),
                            r'%r': args.realm
                        }
                    )

                    self.success('Dumping {} -> {}'.format(name, dest))
                    context['last_name'] = name
                    if context['last_fobj']:
                        context['last_fobj'].write(u'\n]')
                        context['last_fobj'].close()

                    context['last_fobj'] = io_open(
                        dest, 'w+', encoding='utf-8')

                    context['last_fobj'].write(u'[\n')

                for record in from_tuple_deep(payload):
                    if is_first:
                        is_first = False
                    else:
                        context['last_fobj'].write(u',')

                    record_json = dumps(
                        record, indent=2, sort_keys=True,
                        default=json_default,
                        ensure_ascii=False
                    )

                    context['last_fobj'].write(record_json)

        def on_complete():
            if context['last_fobj']:
                context['last_fobj'].write(u']')
                context['last_fobj'].close()
                context['last_fobj'] = None

            if context['last_name']:
                self.success('Completed {}'.format(context['last_name']))
                context['last_name'] = None

                self.success('Dump completed')

            completion.set()

        self.terminate = addump(
            on_data, on_complete,
            args.realm, args.filter or args.target, not args.full
        )

        completion.wait()

    def bind(self, args):
        bind = self.client.remote('ad', 'bind', False)
        completion = Event()

        def on_data(payload):
            if isinstance(payload, tuple):
                self.info(List(payload[1], caption=payload[0]))
            else:
                self.info(payload)

        def on_completed(success, payload):
            try:
                if success:
                    self.success('Bound to server: {}'.format(payload))
                else:
                    self._show_exception(payload)
            finally:
                completion.set()

        self.terminate = bind(
            on_data, on_completed,
            args.realm, args.ldap_server, args.global_catalog, args.recv_timeout,
            args.domain, args.username, args.password,
            args.root
        )

        completion.wait()

    def interrupt(self):
        if self.terminate:
            self.terminate()
        else:
            raise NotImplementedError()
