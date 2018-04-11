# -*- coding: utf-8 -*-
from pupylib.PupyModule import config, PupyArgumentParser, PupyModule

__class_name__="pwd"

@config(cat="admin")
class pwd(PupyModule):
    """ Get current working dir """
    is_module=False

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="pwd", description=cls.__doc__)

    def run(self, args):
        try:
            getcwd = self.client.remote('os', 'getcwdu', False)
            self.success(getcwd())
        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
