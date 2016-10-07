# -*- coding: UTF8 -*-
from pupylib.PupyModule import *

__class_name__="GetDomain"

@config(compat="windows", cat="admin")
class GetDomain(PupyModule):
    """ Get primary domain controller """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="getdomain", description=self.__doc__)

    def run(self, args):
        self.client.load_package("pupwinutils.getdomain")
        primary_domain = self.client.conn.modules["pupwinutils.getdomain"].get_domain_controller()
        if not primary_domain:
            self.error("This host is not part of a domain.")
        else:
            self.success("Primary domain controller: %s" % primary_domain)
