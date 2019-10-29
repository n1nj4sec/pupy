# -*- encoding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Table


@config(cat='creds')
class NetCreds(PupyModule):
    ''' Manage saved authentication information '''

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(
            prog='netcreds', description=cls.__doc__
        )

        commands = cls.arg_parser.add_subparsers(title='actions')

        add = commands.add_parser('add', help='Add credential')
        add.add_argument('username', help='Username')
        add.add_argument('-P', '--password', help='Password')
        add.add_argument('-s', '--schema', help='Schema')
        add.add_argument('-d', '--domain', help='Domain')
        add.add_argument('-p', '--port', type=int, help='Port')
        add.add_argument('-r', '--realm', help='Realm')
        add.add_argument('-a', '--hostname', help='Hostname / address')
        add.add_argument('-i', '--ip', help='IP address')
        add.add_argument('-f', '--path', help='Path')
        add.add_argument('custom', nargs='*', help='Custom options, key=value')
        add.set_defaults(action=cls.add)

        remove = commands.add_parser('del', help='Delete credential which can be found using these flags')
        remove.add_argument('-u', '--username', help='Username')
        remove.add_argument('-s', '--schema', help='Schema')
        remove.add_argument('-d', '--domain', help='Domain')
        remove.add_argument('-p', '--port', type=int, help='Port')
        remove.add_argument('-r', '--realm', help='Realm')
        remove.add_argument('-a', '--hostname', help='Hostname / address')
        remove.add_argument('-i', '--ip', help='IP address')
        remove.add_argument('-f', '--path', help='Path')
        remove.set_defaults(action=cls.remove)

        find = commands.add_parser('list', help='List credentials which can be found using these flags')
        find.add_argument('-u', '--username', help='Username')
        find.add_argument('-s', '--schema', help='Schema')
        find.add_argument('-d', '--domain', help='Domain')
        find.add_argument('-p', '--port', type=int, help='Port')
        find.add_argument('-r', '--realm', help='Realm')
        find.add_argument('-a', '--hostname', help='Hostname / address')
        find.add_argument('-i', '--ip', help='IP address')
        find.add_argument('-f', '--path', help='Path')
        find.set_defaults(action=cls.find)

        clear = commands.add_parser('clear', help='Delete all credentials')
        clear.set_defaults(action=cls.clear)

    def run(self, args):
        args.action(self, args)

    def _draw_creds(self, creds):
        columns = [
            'schema', 'hostname', 'ip', 'port', 'path', 'domain',
            'username', 'password', 'realm'
        ]

        objects = []

        for cred in creds:
            objects.append(dict(cred))

        self.log(Table(objects, columns))


    def find(self, args):
        find_creds = self.client.remote('network.lib.netcreds', 'find_all_creds')
        creds = find_creds(
            args.schema, args.hostname or args.ip, args.port, args.username,
            args.realm, args.domain, args.path, True
        )

        self._draw_creds(creds)

    def add(self, args):
        if not args.username:
            self.error('Username required')
            return

        add_cred = self.client.remote('network.lib.netcreds', 'add_cred')
        add_cred(
            args.username, args.password, args.domain, args.schema,
            args.hostname, args.ip, args.port, args.realm, args.path,
            **dict(item.split('=', 1) for item in args.custom)
        )

    def remove(self, args):
        remove_creds = self.client.remote('network.lib.netcreds', 'remove_creds')
        remove_creds(
            args.schema, args.hostname or args.ip, args.port, args.username,
            args.realm, args.domain, args.path
        )

    def clear(self, args):
        clear_creds = self.client.remote('network.lib.netcreds', 'clear_creds')
        clear_creds()
