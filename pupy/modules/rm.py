# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="rm"

@config(cat="admin")
class rm(PupyModule):
    """ remove a file or a directory """

    is_module = False
    dependencies = ['pupyutils.basic_cmds']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="rm", description=cls.__doc__)
        cls.arg_parser.add_argument('path', type=str, action='store')

    def run(self, args):
        try:
            rm = self.client.remote('pupyutils.basic_cmds', 'rm', False)

            r = rm(args.path)
            if r:
                self.log(r)
        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
            return
