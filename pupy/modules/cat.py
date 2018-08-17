# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Pygment
from pupylib.PupyCompleter import remote_path_completer
from pygments.lexers import guess_lexer, guess_lexer_for_filename

textchars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})

def is_binary(text):
    return bool(text.translate(None, textchars))

__class_name__="cat"

@config(cat="admin")
class cat(PupyModule):
    """ show contents of a file """
    is_module=False
    dependencies = ['pupyutils.basic_cmds']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="cat", description=cls.__doc__)
        cls.arg_parser.add_argument('-N', type=int, help='Tail lines')
        cls.arg_parser.add_argument('-n', type=int, help='Head lines')
        cls.arg_parser.add_argument('-G', type=str, help='Grep sequence')
        cls.arg_parser.add_argument('-E', type=str, help='Set encoding of text file')
        cls.arg_parser.add_argument(
            '-C', '--color', action='store_true', help='Enable coloring (pygments)')
        cls.arg_parser.add_argument('path', type=str, completer=remote_path_completer)

    def run(self, args):
        try:
            cat = self.client.remote('pupyutils.basic_cmds', 'cat', False)
            r = cat(args.path, args.N, args.n, args.G, args.E)
            if r:
                lexer = None

                if is_binary(r):
                    lexer = False
                    try:
                        import hexdump
                        from pygments.lexers.hexdump import HexdumpLexer
                        result = []

                        for line in hexdump.dumpgen(r):
                            if args.color:
                                # Change to something HexdumpLexer knows
                                result.append(line[:8] + ' ' + line[9:60] + '|' + line[60:] + '|')
                            else:
                                result.append(line)

                        r = '\n'.join(result)
                        if args.color:
                            lexer = HexdumpLexer()

                    except Exception, e:
                        r = '[ BINARY FILE ]'
                        lexer = False

                if args.color:
                    if lexer is None and '*' not in args.path:
                        try:
                            lexer = guess_lexer_for_filename(args.path, r)
                        except:
                            pass

                    if lexer is None and not args.N:
                        try:
                            lexer = guess_lexer(r)
                        except:
                            pass

                if lexer:
                    r = Pygment(lexer, r)

                self.log(r)

        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
