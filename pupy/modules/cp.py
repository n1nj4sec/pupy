# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

from pupy.pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupy.pupylib.PupyCompleter import remote_path_completer, remote_dirs_completer

if sys.version_info.major > 2:
    basestring = str

__class_name__="cp"


@config(cat="admin")
class cp(PupyModule):
    """ copy file or directory """
    is_module=False

    dependencies = ['pupyutils.basic_cmds']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="cp", description=cls.__doc__)
        cls.arg_parser.add_argument(
            'src', type=str, action='store', completer=remote_path_completer,
        )

        cls.arg_parser.add_argument(
            'dst', type=str, action='store',
            completer=remote_dirs_completer
        )

    def run(self, args):
        try:
            cp = self.client.remote('pupyutils.basic_cmds', 'cp')
            r = cp(args.src, args.dst)
            if r:
                self.log(r)

        except Exception as e:
            self.error(
                ' '.join(x for x in e.args if isinstance(x, basestring))
            )
