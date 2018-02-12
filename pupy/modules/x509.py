# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from M2Crypto.X509 import load_cert_string

__class_name__='x509'

@config(cat='admin')
class x509(PupyModule):
    ''' Fetch certificate from server '''

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='x509', description=self.__doc__)
        self.arg_parser.add_argument('host', help='Address')
        self.arg_parser.add_argument('port', type=int, help='Port')
        self.arg_parser.add_argument('-t', '--text', action='store_true', default=False,
                                     help='Convert to text')


    def run(self, args):
        get_server_certificate = self.client.remote('ssl', 'get_server_certificate')

        cert = get_server_certificate((args.host, args.port))
        if args.text:
            cert = load_cert_string(cert).as_text()

        self.log(cert)
