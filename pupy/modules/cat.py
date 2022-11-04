# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

from pupy.pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupy.pupylib.PupyOutput import Pygment, Hex
from pupy.pupylib.PupyCompleter import remote_path_completer
from pygments.lexers import guess_lexer, guess_lexer_for_filename
from pupy.network.lib.convcompat import is_binary, DEFAULT_MB_ENCODING

if sys.version_info.major > 2:
    basestring = str

__class_name__ = 'cat'


@config(cat="admin")
class cat(PupyModule):
    """ show contents of a file """
    is_module = False
    dependencies = ['pupyutils.basic_cmds']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(
            prog='cat', description=cls.__doc__
        )
        cls.arg_parser.add_argument('-N', type=int, help='Tail lines')
        cls.arg_parser.add_argument('-n', type=int, help='Head lines')

        grep = cls.arg_parser.add_mutually_exclusive_group()
        grep.add_argument('-G', help='Grep sequence')
        grep.add_argument('-g', help='Grep out sequence')

        cls.arg_parser.add_argument(
            '-E', type=str, help='Set encoding of text file'
        )
        cls.arg_parser.add_argument(
            '-C', '--color', action='store_true',
            help='Enable coloring (pygments)'
        )
        cls.arg_parser.add_argument(
            'path', type=str, completer=remote_path_completer
        )

    def print_content(self, args, content):
        lexer = None

        if is_binary(content):
            content = Hex(content, args.color)

        elif args.color:
            if lexer is None and '*' not in args.path:
                try:
                    lexer = guess_lexer_for_filename(args.path, content)
                except:
                    pass

            if lexer is None and not args.N:
                try:
                    lexer = guess_lexer(content)
                except:
                    pass

            if lexer:
                content = Pygment(lexer, content)

        self.log(content)

    def run(self, args):
        try:
            cat = self.client.remote('pupyutils.basic_cmds', 'cat', False)

            grep = None
            filter_out = False
            if args.G:
                grep = args.G
            elif args.g:
                grep = args.g
                filter_out = True

            results = cat(
                args.path, args.N, args.n, grep, args.E, filter_out
            )

            if not results:
                return

            for result in results:
                self.print_content(args, result)

        except Exception as e:
            self.error(
                ' '.join(x for x in e.args if isinstance(x, basestring))
            )
