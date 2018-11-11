# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Color, TruncateToTerm, Table

__class_name__="Services"

ADMINS = (r'NT AUTHORITY\SYSTEM', 'LOCALSYSTEM', 'root')
LIKELY_KNOWN = (
    'svchost.exe', 'lsass.exe', 'spoolsv.exe', 'TrustedInstaller.exe',
    'wmpnetwk.exe', 'SearchIndexer.exe'
)

@config(cat='admin', compat=['windows','linux'])
class Services(PupyModule):
    """ list services """

    dependencies = {
        'windows': ['pupyps'],
        'linux': ['dbus', 'services']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="services", description=cls.__doc__)
        cls.arg_parser.add_argument('-i', '--info', action='store_true', help='Show more info')
        cls.arg_parser.add_argument('-a', '--all', action='store_true', help='Show all services')
        cls.arg_parser.add_argument('-D', '--display-name', action='store_true',
                                    help='Show display name instead of name')

    def run(self, args):
        is_linux = False

        if self.client.is_linux():
            get_services = self.client.remote('services', 'get_services_systemd')
            is_linux = True
        elif self.client.is_windows():
            get_services = self.client.remote('pupyps', 'get_win_services')
        else:
            raise ValueError('Unsupported target')

        services = get_services()

        columns = [('pid', 'PID'), ('name', 'SERVICE'), ('binpath', 'PATH')]
        if args.info:
            columns = [('pid', 'PID'), ('name', 'SERVICE'), ('username', 'USER'), ('binpath', 'PATH')]

        if args.display_name:
            columns = [
                x if x[0] != 'name' else ('display_name', 'SERVICE') for x in columns
            ]

        data = []

        for service in services:

            username = service.get('username')
            status = service.get('status')
            binpath = service.get('binpath')

            color = None
            if not status == 'running':
                if not args.all:
                    continue

                color = 'grey'
            elif all([x not in binpath for x in LIKELY_KNOWN]) and not is_linux:
                color = 'cyan'
                if username.upper() in ADMINS:
                    color = 'lightyellow'

            if color is not None:
                service = {
                    k:Color(v if v is not None else '', color) for k,v in service.iteritems()
                }

            data.append(service)


        self.log(TruncateToTerm(Table(data, columns)))
