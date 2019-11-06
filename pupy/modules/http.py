# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Pygment, Table, NewLine
from pygments.lexers import guess_lexer

__class_name__='http'

@config(cat='admin')
class http(PupyModule):
    ''' Trivial Get/Post requests via HTTP protocol '''
    is_module=False

    dependencies = []

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='http', description=cls.__doc__)
        cls.arg_parser.add_argument('-H', '--header', default=[], action='append',
                                         help='User-Agent=Mozilla X-Forwarded-For=127.0.0.1')
        cls.arg_parser.add_argument('-C', '--color', action='store_true', help='Try to colorize output')
        cls.arg_parser.add_argument('-I', '--get-headers', action='store_true', default=False, help='Return headers')
        cls.arg_parser.add_argument('-R', '--no-result', action='store_true', default=False,
                                    help='Do not show result')
        cls.arg_parser.add_argument('-P', '--proxy', help='Proxy URI (socks://127.0.0.1:1234)')
        cls.arg_parser.add_argument('-o', '--output', help='Output to file')
        cls.arg_parser.add_argument('-i', '--input', help='Input from file (POST)')
        cls.arg_parser.add_argument('-v', '--verify', default=False, action='store_true', help='Verify certificate')
        cls.arg_parser.add_argument('-r', '--follow-redirects', default=False, action='store_true',
                                     help='Follow redirects')
        cls.arg_parser.add_argument('url', help='url')
        cls.arg_parser.add_argument('data', nargs='*', default=[], help='Data (POST/urlencode)')

    def run(self, args):
        tinyhttp = self.client.remote('network.lib.tinyhttp')

        if '://' not in args.url:
            args.url = 'http://' + args.url

        http = tinyhttp.HTTP(
            proxy=args.proxy,
            noverify=not args.verify,
            follow_redirects=args.follow_redirects,
            headers=[
                tuple(x.split('=', 1)) for x in (
                    args.header if type(args.header) == list else [
                        args.header
                    ]
                )
            ]
        )

        try:
            result = None
            if args.input or args.data:
                result = self.client.obtain_call(
                    http.post,
                    args.url,
                    data=[
                          tuple(x.split('=', 1)) for x in args.data
                    ],
                    file=args.input,
                    save=args.output,
                    return_headers=args.get_headers,
                    code=args.get_headers,
                    return_url=args.get_headers,
                )
            else:
                result = self.client.obtain_call(
                    http.get,
                    args.url,
                    save=args.output,
                    return_headers=args.get_headers,
                    code=args.get_headers,
                    return_url=args.get_headers,
                )

            if args.get_headers:
                result, url, code, headers = result
                self.log(Table([
                    {
                        'HEADER': header,
                        'VALUE': value,
                    } for header, value in headers.iteritems()
                ], ['HEADER', 'VALUE'], caption='{} {}'.format(code, url)))

                if not args.no_result:
                    self.log(NewLine())

            if result and not args.no_result:
                if args.color:
                    try:
                        lexer = guess_lexer(result)
                        result = Pygment(lexer, result)
                    except:
                        pass

                self.log(result)

        except Exception, e:
            if hasattr(e, 'reason'):
                code = getattr(e, 'code', None)
                message = '{} {} ({})'.format(code or '?', e.reason, e.filename or '')
                if code and (code / 100 < 4):
                    self.warning(message)
                else:
                    self.error(message)

                return

            elif hasattr(e, 'msg'):
                message = e.msg
            else:
                message = e.message
            self.error('Error: {}'.format(message))
