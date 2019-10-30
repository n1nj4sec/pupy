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
        result.append({
            'Type': ace['TypeName'][:-4],
            'Sid': ace['Ace']['Sid'].formatCanonical(),
            'Mask': LDAPAclMaskToSet(ace['Ace']['Mask'])
        })

    return result


def LDAPAclOwnerToDict(owner):
    if not owner:
        return None

    return owner.formatCanonical()


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
        return format_sid(att[4:].decode('hex'))

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


def from_tuple_deep(obj):
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

    elif kind == MAP:
        return {
            k: formatAttribute(k, from_tuple_deep(v)) for (k, v) in data
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
        cls.arg_parser.add_argument('realm', help='Realm to dump')
        cls.arg_parser.add_argument('-l', '--ldap-server', help='DNS address of LDAP server')
        cls.arg_parser.add_argument(
            '-G', '--global-catalog', default=False, action='store_true',
            help='Use AD Global catalg')
        cls.arg_parser.add_argument('-T', '--recv-timeout', default=60, help='Socket read timeout')
        cls.arg_parser.add_argument('-u', '--username', help='Username to authenticate')
        cls.arg_parser.add_argument('-p', '--password', help='Password to authenticate')
        cls.arg_parser.add_argument('-d', '--domain', help='Domain for Username')
        cls.arg_parser.add_argument('-r', '--root', help='LDAP root')
        cls.arg_parser.add_argument('-f', '--filter', help='LDAP custom filter')

        commands = cls.arg_parser.add_subparsers(title='commands')

        info = commands.add_parser('info', help='Info about current AD context')
        info.set_defaults(func=cls.getinfo)

        dump = commands.add_parser('dump', help='Dump results of large searches')
        dump.add_argument(
            '-f', '--full', default=False,
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
            'term', help='Search filter',
            default='(objectClass=domain)',
        )
        search.add_argument(
            'attributes', nargs='?', default=NO_ATTRIBUTES,
            help='Attributes to search (Use * for ALL, default none)'
        )
        search.add_argument(
            '-B', '--base', default=False, action='store_true',
            help='Use base search instead of subtree search. Default: False'
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


    def run(self, args):
        args.func(self, args)

    def search(self, args):
        search = self.client.remote('ad', 'search')

        ok, result = search(
            args.realm, args.ldap_server, args.global_catalog, args.recv_timeout,
            args.domain, args.username, args.password,
            args.root,

            args.term, args.attributes, args.base,
            args.amount, args.timeout,
            False
        )

        if not ok:
            self.error(result)
            return

        if not args.attributes or args.attributes == NO_ATTRIBUTES:
            result = tuple(
                record['dn'] for record in from_tuple_deep(result)
            )

            self.log(
                List(
                    result, caption='Search: ' + args.term
                )
            )
        else:
            result = tuple(
                record for record in from_tuple_deep(result)
                if 'dn' in record
            )

            formatted_json = dumps(
                result,
                indent=2, sort_keys=True,
                default=json_default,
                ensure_ascii=False
            )

            self.log(
                Pygment(lexers.JsonLexer(), formatted_json)
            )

    def childs(self, args):
        childs = self.client.remote('ad', 'childs')
        ok, result = childs(
            args.realm, args.ldap_server, args.global_catalog, args.recv_timeout,
            args.domain, args.username, args.password,
            args.root
        )

        if not ok:
            self.error(result)
            return

        i_am, rootdn, childs = result

        self.log(List(childs, caption='Root: {} Whoami: {}'.format(rootdn, i_am)))

    def getinfo(self, args):
        info = self.client.remote('ad', 'info')
        desc = info(
            args.realm, args.ldap_server, args.global_catalog, args.recv_timeout,
            args.domain, args.username, args.password,
            args.root
        )

        desc = from_tuple_deep(desc)
        idesc = desc['info']

        infos = []
        infos.append(
            List([
                'Bind: ' + desc['bind'],
                'Root: ' + desc['root'],
                'LDAP: ' + desc['ldap'],
                'DNS: ' + desc['dns'][4][0],
                'Schema: ' + idesc['schema_entry'],
                'Versions: ' + ', '.join(
                    str(version) for version in idesc['supported_ldap_versions']
                ),
                'SASL Mechs: ' + ', '.join(
                    mech for mech in idesc['supported_sasl_mechanisms']
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

        if idesc['alt_servers']:
            infos.append(
                List(idesc['alt_servers'], caption='Alternate servers')
            )

        if idesc['naming_contexts']:
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

        self.info('Starting dump for realm {}{}'.format(
            args.realm,
            ' ldap={}'.format(
                args.ldap_server
            ) if args.ldap_server else ''))

        self.terminate = addump(
            on_data, on_complete,
            args.realm, args.ldap_server, args.global_catalog, args.recv_timeout,
            args.filter or args.target, not args.full,
            args.domain, args.username, args.password,
            args.root
        )

        completion.wait()

    def interrupt(self):
        if self.terminate:
            self.terminate()
        else:
            raise NotImplementedError()
