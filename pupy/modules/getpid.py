# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain
from modules.lib.utils.shell_exec import shell_exec
import re, os

__class_name__="PsModule"

@config(cat="admin")
class PsModule(PupyModule):
    """ list process information """
    is_module=False

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="getpid", description=self.__doc__)

    def run(self, args):
        getpid = self.client.remote('os', 'getpid')
        pid = getpid()
        self.log('PID: {}'.format(pid))
