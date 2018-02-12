# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain
from modules.lib.utils.shell_exec import shell_exec
import re, os

__class_name__="PsModule"

@config(cat="admin")
class PsModule(PupyModule):
    """ list parent process information """
    is_module=False

    dependencies = {
        'windows': [ 'pupwinutils.processes' ]
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="getppid", description=self.__doc__)

    def run(self, args):
        if self.client.is_windows():
            get_current_ppid = self.client.remote('pupwinutils.processes', 'get_current_ppid')
            outputlist = get_current_ppid()
            for out in outputlist:
                self.log('%s: %s' % (out, outputlist[out]))
            return # quit
        else:
            getppid = self.client.remote('os', 'getppid')
            self.log('PPID: {}'.format(getppid()))
