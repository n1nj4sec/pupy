# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from M2Crypto.X509 import load_cert_string

__class_name__='x509'

@config(cat='admin')
class x509(PupyModule):
    ''' Fetch certificate from server '''

    dependencies = [ 'pupyutils.basic_cmds' ]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='x509', description=cls.__doc__)
        cls.arg_parser.add_argument('host', help='Address or path')
        cls.arg_parser.add_argument('port', type=int, default=443, nargs='?', help='Port')
        cls.arg_parser.add_argument('-F', '--file', action='store_true', default=False,
                                     help='Force treat host as file path')
        cls.arg_parser.add_argument('-R', '--raw', action='store_true', default=False,
                                     help='Do not convert to text')


    def run(self, args):
        if args.file or '/' in args.host or '\\' in args.host:
            cat = self.client.remote('pupyutils.basic_cmds', 'cat', False)
            cert = cat(args.host)
        else:
            get_server_certificate = self.client.remote('ssl', 'get_server_certificate')
            cert = get_server_certificate((args.host, args.port))

        if not args.raw:
            cert = load_cert_string(cert).as_text()

        self.log(cert)
