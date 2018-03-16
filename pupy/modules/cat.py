# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.PupyOutput import Pygment
from pupylib.PupyCompleter import remote_path_completer
from pygments.lexers import guess_lexer, guess_lexer_for_filename

__class_name__="cat"

@config(cat="admin")
class cat(PupyModule):
    """ show contents of a file """
    is_module=False
    dependencies = [ 'pupyutils.basic_cmds' ]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="cat", description=cls.__doc__)
        cls.arg_parser.add_argument('-N', type=int, help='Tail lines')
        cls.arg_parser.add_argument('-n', type=int, help='Head lines')
        cls.arg_parser.add_argument('-G', type=str, help='Grep sequence')
        cls.arg_parser.add_argument(
            '-C', '--color', action='store_true', help='Enable coloring (pygments)')
        cls.arg_parser.add_argument('path', type=str, completer=remote_path_completer)

    def run(self, args):
        try:
            cat = self.client.remote('pupyutils.basic_cmds', 'cat', False)
            r = cat(args.path, args.N, args.n, args.G)
            if r:
                lexer = None
                if args.color:
                    if not '*' in args.path:
                        try:
                            lexer = guess_lexer_for_filename(args.path, r)
                        except:
                            pass

                    if not lexer and not args.N:
                        try:
                            lexer = guess_lexer(r)
                        except:
                            pass

                if lexer:
                    r = Pygment(lexer, r)

                self.log(r)

        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
