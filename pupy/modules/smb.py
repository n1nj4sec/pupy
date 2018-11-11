# -*- coding: utf-8 -*-

import os
import ntpath
import StringIO

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.utils.rpyc_utils import obtain

__class_name__="SMB"

class SMBError(Exception):
    pass

@config(cat="admin")
class SMB(PupyModule):
    ''' Copy files via SMB protocol '''

    max_clients = 1
    dependencies = [
        'unicodedata', 'idna', 'encodings.idna',
        'impacket', 'pupyutils.psexec'
    ]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='smb', description=cls.__doc__)
        cls.arg_parser.add_argument('-u', '--username', default='', help='Username')
        cls.arg_parser.add_argument('-P', '--port', default=445, type=int, help='Port')
        cls.arg_parser.add_argument('-p', '--password', default='', help='Password')
        cls.arg_parser.add_argument('-d', '--domain', default='', help='Domain')
        cls.arg_parser.add_argument('-H', '--hash', default='', help='NTLM hash')
        cls.arg_parser.add_argument('-T', '--timeout', default=30, type=int, help='Timeout')
        cls.arg_parser.add_argument('-c', '--codepage', default=None, help='Codepage')

        commands = cls.arg_parser.add_subparsers(dest="command")
        cp = commands.add_parser('cp')
        cp.add_argument('src', help='Source')
        cp.add_argument('dst', help='Destination')
        cp.set_defaults(func=cls.cp)

        ls = commands.add_parser('ls')
        ls.add_argument('dst', help='Destination')
        ls.set_defaults(func=cls.ls)

        cat = commands.add_parser('cat')
        cat.add_argument('remote', help='Remote file (be careful!)')
        cat.set_defaults(func=cls.cat)

        rm = commands.add_parser('rm')
        rm.add_argument('dst', help='Destination')
        rm.set_defaults(func=cls.rm)

        mkdir = commands.add_parser('mkdir')
        mkdir.add_argument('dst', help='Destination')
        mkdir.set_defaults(func=cls.mkdir)

        rmdir = commands.add_parser('rmdir')
        rmdir.add_argument('dst', help='Destination')
        rmdir.set_defaults(func=cls.rmdir)

        shares = commands.add_parser('shares')
        shares.add_argument('host', help='Host')
        shares.set_defaults(func=cls.shares)

    def run(self, args):
        try:
            args.func(self, args)
        except SMBError, e:
            self.error(str(e))

    def get_ft(self, args, host):
        create_filetransfer = self.client.remote(
            'pupyutils.psexec', 'create_filetransfer', False)

        connection = None
        error = None

        connection, error = create_filetransfer(
            host, args.port,
            args.username, args.domain,
            args.password, args.hash,
            timeout=args.timeout
        )

        if error:
            raise SMBError(error)

        return connection

    def shares(self, args):
        host = args.host
        host = host.replace('\\', '//')
        if host.startswith('//'):
            host = host[2:]

        ft = self.get_ft(args, host)
        if not ft.ok:
            self.error(ft.error)
            return

        for share in obtain(ft.shares()):
            self.log(share)

        if not ft.ok:
            self.error(ft.error)

    def parse_netloc(self, line, partial=False, codepage=None):
        line = line.replace('\\', '/')
        if not line.startswith('//'):
            raise ValueError('Invalid network format')

        if not type(line) == unicode:
            line = line.decode('utf-8')

        if codepage:
            line = line.encode(codepage, errors='replace')

        remote = line[2:].split('/')

        if partial:
            if len(remote) == 0:
                raise ValueError('Empty network specification')

            if not (remote[0]):
                raise ValueError('Host is empty')

            host = remote[0]
            if len(remote) > 1:
                share = remote[1]
            else:
                share = ''

            if len(remote) > 2:
                path = ntpath.normpath('\\'.join(remote[2:]))
                if remote[-1] == '':
                    path += '\\'
            else:
                path = ''

            return host, share, path

        else:
            if len(remote) < 3 or not all(remote[:2]):
                raise ValueError('Invalid network format')

            return remote[0], remote[1], ntpath.normpath('\\'.join(remote[2:]))

    def ls(self, args):
        try:
            host, share, path = self.parse_netloc(args.dst, partial=True, codepage=args.codepage)
        except Exception, e:
            self.error(e)
            return

        if not share:
            args.host = host
            self.shares(args)
            return

        if not path or path == '.' or path.endswith('\\'):
            path += '*'

        ft = self.get_ft(args, host)
        if not ft.ok:
            self.error(ft.error)
            return

        for name, directory, size, ctime in obtain(ft.ls(share, path)):
            if type(name) != unicode:
                if args.codepage:
                    name = name.decode(args.codepage, errors='replace')
                else:
                    name = name.decode('utf-8', errors='replace')

            self.log(u'%crw-rw-rw- %10d  %s %s' % (
                'd' if directory > 0 else '-', size,
                ctime, name))

        if not ft.ok:
            self.error(ft.error)

    def rm(self, args):
        try:
            host, share, path = self.parse_netloc(args.dst, codepage=args.codepage)
        except Exception, e:
            self.error(str(e))
            return

        ft = self.get_ft(args, host)
        if not ft.ok:
            self.error(ft.error)
            return

        ft.rm(share, path)
        if not ft.ok:
            self.error(ft.error)

    def mkdir(self, args):
        try:
            host, share, path = self.parse_netloc(args.dst, codepage=args.codepage)
        except Exception, e:
            self.error(str(e))
            return

        ft = self.get_ft(args, host)
        if not ft.ok:
            self.error(ft.error)
            return

        ft.mkdir(share, path)
        if not ft.ok:
            self.error(ft.error)

    def rmdir(self, args):
        try:
            host, share, path = self.parse_netloc(args.dst, codepage=args.codepage)
        except Exception, e:
            self.error(str(e))
            return

        ft = self.get_ft(args, host)
        if not ft.ok:
            self.error(ft.error)
            return

        ft.rmdir(share, path)
        if not ft.ok:
            self.error(ft.error)

    def cp(self, args):
        upload = False
        src = args.src.replace('\\', '/')
        dst = args.dst.replace('\\', '/')
        if dst.startswith('//'):
            upload = True
            remote = dst
            local = src
        elif src.startswith('//'):
            remote = src
            local = dst
        else:
            self.error(r'Either src or dst should be network share in (\\HOST\SHARE\PATH) format')
            return

        try:
            host, share, path = self.parse_netloc(remote, codepage=args.codepage)
        except Exception, e:
            self.error(e)
            return

        local = os.path.expandvars(local)
        local = os.path.expanduser(local)

        ft = self.get_ft(args, host)

        if not ft.ok:
            self.error(ft.error)
            return

        if upload:
            if upload and not os.path.isfile(local):
                self.warning('Source file {} not found, try upload remote file'.format(local))
                ft.put(local, share, path)
            else:
                with open(local, 'r+b') as source:
                    ft.put(source.read, share, path)
        else:
            with open(local, 'w+b') as destination:
                ft.get(share, path, destination.write)

        if not ft.ok:
            self.error(ft.error)

    def cat(self, args):
        try:
            host, share, path = self.parse_netloc(args.remote, codepage=args.codepage)
        except Exception, e:
            self.error(e)
            return

        ft = self.get_ft(args, host)
        if not ft.ok:
            self.error(ft.error)
            return

        memobj = StringIO.StringIO()
        ft.get(share, path, memobj.write)

        if ft.ok:
            data = memobj.getvalue()
            if args.codepage:
                try:
                    data = data.decode(args.codepage)
                except:
                    pass

            self.log(data)
        else:
            self.error(ft.error)
