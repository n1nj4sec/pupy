# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__='http'

@config(cat='admin')
class http(PupyModule):
    ''' Trivial Get/Post requests via HTTP protocol '''
    is_module=False

    dependencies = []

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='http', description=self.__doc__)
        self.arg_parser.add_argument('-H', '--headers', default=[], nargs='+',
                                         help='User-Agent=Mozilla X-Forwarded-For=127.0.0.1')
        self.arg_parser.add_argument('-P', '--proxy', help='Proxy URI (socks://127.0.0.1:1234)')
        self.arg_parser.add_argument('-o', '--output', help='Output to file')
        self.arg_parser.add_argument('-i', '--input', help='Input from file (POST)')
        self.arg_parser.add_argument('url', help='url')
        self.arg_parser.add_argument('data', nargs='*', default=[], help='Data (POST/urlencode)')

    def run(self, args):
        HTTP = self.client.conn.modules['network.lib.tinyhttp'].HTTP

        http = HTTP(
            proxy=args.proxy,
            headers=[
                tuple(x.split('=', 1)) for x in args.headers
            ]
        )

        if args.input or args.data:
            self.log(
                http.post(
                    args.url,
                    data=[
                        tuple(x.split('=', 1)) for x in args.data
                    ],
                    file=args.input,
                    save=args.output
                )
            )
        else:
            self.log(
                http.get(args.url, save=args.output)
            )
