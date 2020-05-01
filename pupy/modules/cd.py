# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyCompleter import remote_dirs_completer

if sys.version_info.major > 2:
    basestring = str

__class_name__="cd"


@config(cat="admin")
class cd(PupyModule):
    """ change directory """
    is_module=False

    dependencies = ['pupyutils.basic_cmds']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="cd", description=cls.__doc__)
        cls.arg_parser.add_argument(
            'path', type=str, nargs='?',
            help='path of a specific directory',
            completer=remote_dirs_completer
        )

    def run(self, args):
        try:
            cd = self.client.remote('pupyutils.basic_cmds', 'cd', False)
            r = cd(args.path)
            if r:
                self.log(r)
        except Exception as e:
            self.error(
                ' '.join(x for x in e.args if isinstance(x, basestring))
            )
