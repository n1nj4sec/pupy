# -*- coding: utf-8 -*-
#Author: @n1nj4sec
#Contributor(s): @bobsecq

from pupylib.PupyModule import *

__class_name__="GetPrivsModule"

@config(compat=["windows"], cat="manage")
class GetPrivsModule(PupyModule):
    """ Manage current process privileges """

    dependencies=["pupwinutils.security"]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="getprivs", description=self.__doc__)
        self.arg_parser.add_argument('--get-debug', dest='getdebug', action='store_true', help="Try to get SeDebugPrivilege for the current process")

    def run(self, args):
        if args.getdebug == True:
            EnablePrivilege = self.client.remote('pupwinutils.security', 'EnablePrivilege', False)
            EnablePrivilege('SeDebugPrivilege')
            self.success('SeDebugPrivilege enabled !')
        else:
            get_currents_privs = self.client.remote('pupwinutils.security', 'get_currents_privs', False)
            privs = get_currents_privs()

            self.success('Process privileges:')
            for aPriv in privs:
                self.success('{}'.format(aPriv))
