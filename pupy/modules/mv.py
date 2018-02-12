# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="mv"

@config(cat="admin")
class mv(PupyModule):
    """ move file or directory """
    is_module = False

    dependencies = [ 'pupyutils.basic_cmds' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="mv", description=self.__doc__)
        self.arg_parser.add_argument('src', type=str, action='store')
        self.arg_parser.add_argument('dst', type=str, action='store')

    def run(self, args):
        try:
            mv = self.client.remote('pupyutils.basic_cmds', 'mv')

            r = mv(args.src, args.dst)
            if r:
                self.log(r)

        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
            return
