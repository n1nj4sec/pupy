# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain
from modules.lib.utils.shell_exec import shell_exec
import re, os

__class_name__="PsModule"

@config(cat="admin")
class PsModule(PupyModule):
    """ list parent process information """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="getppid", description=self.__doc__)

    def run(self, args):
        if self.client.is_windows():
            self.client.load_package("psutil")
            self.client.load_package("pupwinutils.processes")
            outputlist=self.client.conn.modules["pupwinutils.processes"].get_current_ppid()
            outputlist=obtain(outputlist) #pickle the list of proxy objects with obtain is really faster
            for out in outputlist:
                self.log('%s: %s' % (out, outputlist[out]))
            return # quit 
        
        elif self.client.is_android():
            all_process = shell_exec(self.client, "ps")
        elif self.client.is_darwin():
            all_process = shell_exec(self.client, "ps aux")
        else:
            all_process = shell_exec(self.client, "ps -aux")

        # used for posix system
        ppid=self.client.conn.modules['os'].getppid()
        for process in all_process.split('\n'):
            p = re.split(r' +', process)
            if len(p)>1:
                pid = p[1]
                if pid == str(ppid):
                    self.log("%s"%(process))
                    break

