# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from pupy.pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__="getuid"

@config(cat="admin")
class getuid(PupyModule):
    """ get username """
    is_module=False
    dependencies = ['pupyutils.basic_cmds']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="getuid", description=cls.__doc__)

    def run(self, args):
        getuid = self.client.remote('pupyutils.basic_cmds', 'getuid')
        self.success(getuid())
