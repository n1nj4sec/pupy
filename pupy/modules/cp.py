# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="cp"

@config(cat="admin")
class cp(PupyModule):
    """ copy file or directory """
    is_module=False

    dependencies = [ 'pupyutils.basic_cmds' ]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="cp", description=cls.__doc__)
        cls.arg_parser.add_argument('src', type=str, action='store')
        cls.arg_parser.add_argument('dst', type=str, action='store')

    def run(self, args):
        try:
            cp = self.client.remote('pupyutils.basic_cmds', 'cp')
            r = cp(args.src, args.dst)
            if r:
                self.log(r)

        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
            return
