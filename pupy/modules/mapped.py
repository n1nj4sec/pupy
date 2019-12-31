# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyCompleter import path_completer

__class_name__ = 'Mapped'

@config(compat='linux')
class Mapped(PupyModule):
    ''' Create virtual mapped path with memfd backed file (if supported) '''

    dependencies = ['mapped']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='mapped', description=cls.__doc__)

        actions = cls.arg_parser.add_mutually_exclusive_group()
        actions.add_argument(
            '-C', '--create', help='Path to local file to upload',
            completer=path_completer
        )
        actions.add_argument(
            '-R', '--remove', action='store_true', help='Remove virtual path'
        )

        cls.arg_parser.add_argument('virtual', help='Virtual path')


    def run(self, args):
        if args.create:
            create = self.client.remote('mapped', 'create_mapped_file')

            with open(args.create, 'rb') as idata:
                create(args.virtual, idata.read())
        else:
            remove = self.client.remote('mapped', 'close_mapped_file')
            remove(args.virtual)
