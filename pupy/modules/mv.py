# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyCompleter import remote_path_completer, remote_dirs_completer

__class_name__="mv"

@config(cat="admin")
class mv(PupyModule):
    """ move file or directory """
    is_module = False

    dependencies = ['pupyutils.basic_cmds']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="mv", description=cls.__doc__)
        cls.arg_parser.add_argument('src', type=str, action='store', completer=remote_path_completer)
        cls.arg_parser.add_argument('dst', type=str, action='store', completer=remote_dirs_completer)

    def run(self, args):
        try:
            mv = self.client.remote('pupyutils.basic_cmds', 'mv')

            r = mv(args.src, args.dst)
            if r:
                self.log(r)

        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
            return
