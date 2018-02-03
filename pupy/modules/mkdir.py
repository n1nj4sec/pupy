# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="mkdir"

@config(cat="admin")
class mkdir(PupyModule):
    """ create an empty directory """

    is_module=False
    dependencies = [ 'pupyutils.basic_cmds' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="mkdir", description=self.__doc__)
        self.arg_parser.add_argument('dir', type=str, help='directory name')

    def run(self, args):
        try:
            r = self.client.conn.modules["pupyutils.basic_cmds"].mkdir(args.dir)
            if r:
                self.log(r)
        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
            return
