# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from argparse import REMAINDER

from netaddr import IPNetwork

from pupylib.PupyOutput import Table, List
from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__ = 'RWMIC'


def _stringify(x):
    if type(x) in (str, unicode):
        return x
    elif type(x) in (list, tuple):
        return ';'.join(_stringify(y) for y in x)
    elif type(x) is None:
        return ''
    else:
        return str(x)


@config(category='admin')
class RWMIC(PupyModule):
    ''' Remote WMI query using WQL '''

    dependencies = [
        'unicodedata', 'idna', 'encodings.idna',
        'impacket', 'ntpath',
        'calendar', 'pupyutils.psexec'
    ]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="rwmic", description=cls.__doc__)
        cls.arg_parser.add_argument("-u", metavar="USERNAME", dest='user', default='',
                                    help="Username, if omitted null session assumed")
        cls.arg_parser.add_argument("-p", metavar="PASSWORD", dest='passwd', default='', help="Password")
        cls.arg_parser.add_argument("-H", metavar="HASH", dest='hash', default='', help='NTLM hash')
        cls.arg_parser.add_argument("-d", metavar="DOMAIN", dest='domain', default="WORKGROUP",
                                    help="Domain name (default WORKGROUP)")
        cls.arg_parser.add_argument("-s", metavar="SHARE", dest='share', default="C$",
                                    help="Specify a share (default C$)")
        cls.arg_parser.add_argument("-S", dest='noout', action='store_true', help="Do not wait for command output")
        cls.arg_parser.add_argument("-T", metavar="TIMEOUT", dest='timeout', default=30, type=int,
                                    help="Try to set this timeout")
        cls.arg_parser.add_argument("--port", dest='port', type=int, choices={135, 445}, default=135,
                                    help="RMI port (default 135)")
        cls.arg_parser.add_argument("target", nargs=1, type=str, help="The target range or CIDR identifier")

        cls.arg_parser.add_argument('query', nargs=REMAINDER)

    def run(self, args):
        wql = self.client.remote('pupyutils.psexec', 'wql')
        if args.query:
            cmdline = ' '.join(args.query)

        else:
            cmdline = 'SELECT DatabaseDirectory,BuildVersion,LoggingDirectory '\
              'FROM Win32_WMISetting'

        if "/" in args.target[0]:
            hosts = IPNetwork(args.target[0])
        else:
            hosts = list()
            hosts.append(args.target[0])

        for host in hosts:
            try:
                columns, values = wql(
                    str(host), args.port,
                    args.user,  args.domain,
                    args.passwd, args.hash,
                    cmdline, args.timeout
                )

                if not columns:
                    return
                elif len(columns) == 1:
                    self.log(List(list(
                        _stringify(x[0]) for x in values), caption=columns[0]))
                else:
                    if not values:
                        return

                    elif len(values) == 1:
                        records = [
                            {
                                'KEY': column,
                                'VALUE': _stringify(values[0][idx])
                            } for idx, column in enumerate(columns)
                        ]
                        self.log(Table(records, ['KEY', 'VALUE']))
                    else:
                        records = [
                            {
                                column: _stringify(value[idx]) for
                                idx, column in enumerate(columns)
                            } for value in values
                        ]
                        self.log(Table(records, columns))

            except Exception as e:
                self.error(e)
