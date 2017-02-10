# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain
from modules.lib.utils.shell_exec import shell_exec

__class_name__="PsModule"

@config(cat="admin")
class PsModule(PupyModule):
    """ list processes """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="ps", description=self.__doc__)
        self.arg_parser.add_argument('--all', '-a', action='store_true', help='more info')

    def run(self, args):
        if self.client.is_windows():
            self.client.load_package("psutil")
            self.client.load_package("pupwinutils.processes")
            outputlist=self.client.conn.modules["pupwinutils.processes"].enum_processes()
            outputlist=obtain(outputlist) #pickle the list of proxy objects with obtain is really faster
            columns=['username', 'pid', 'arch', 'exe']
            if args.all:
                columns=['username', 'pid', 'arch', 'name', 'exe', 'cmdline', 'status']
                for dic in outputlist:
                    for c in columns:
                        if c in dic and dic[c] is None:
                            dic[c]=""
                    dic["cmdline"]=' '.join(dic['cmdline'][1:])
            else:
                for dic in outputlist:
                    if 'exe' in dic and not dic['exe'] and 'name' in dic and dic['name']:
                        dic['exe']=dic['name'].encode('utf-8', errors='replace')
                    if 'username' in dic and dic['username'] is None:
                        dic['username']=""
            self.rawlog(self.formatter.table_format(outputlist, wl=columns))
        elif self.client.is_android():
            self.log(shell_exec(self.client, "ps"))
        elif self.client.is_darwin():
            self.log(shell_exec(self.client, "ps aux"))
        else:
            self.log(shell_exec(self.client, "ps -aux"))

