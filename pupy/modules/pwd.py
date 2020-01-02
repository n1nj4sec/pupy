# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
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
        except Exception as e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
