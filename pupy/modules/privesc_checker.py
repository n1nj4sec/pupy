# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import os
import subprocess

__class_name__="PrivEsc_Checker"
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))

@config(compat="linux", category="privesc")
class PrivEsc_Checker(PupyModule):
    """ Linux Privilege Escalation Scripts """
    
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="PrivEsc_Checker", description=self.__doc__)
        self.arg_parser.add_argument("--linenum", dest='linenum', action='store_true', help="Run Linenum sh script (https://github.com/rebootuser/LinEnum)")
        self.arg_parser.add_argument("--thorough-tests", dest='thoroughtests', action='store_true', help="Run script with all options (can take time)")
        self.arg_parser.add_argument("--output-file", dest='outputfile', default=None, help="Store results in this file")
        self.arg_parser.add_argument("--shell", dest='shell', default="/bin/bash", help="Shell to use when it is a .sh script")

    def run(self, args):
        if args.linenum == True:
            self.success("Running Lineum sh script on the target with the {0} shell on the target...".format(args.shell))
            if self.client.conn.modules.os.path.isfile(args.shell) == False:
                self.error("{0} does not exist on the target's system!".format(args.shell))
                self.error("You have to choose a valid shell")
                return -1
            code = open(os.path.join(ROOT, "external", "linenum", "linenum.sh"), 'r').read()
            #output = self.client.conn.modules.subprocess.check_output(code, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell = True)
            if args.thoroughtests == True:
                self.success("Thorough tests enabled! Can take time...")
                code = "thorough=1;\n"+code
            self.success("Lineum script started...")
            p = self.client.conn.modules.subprocess.Popen(code, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True, executable=args.shell)
            output, err = p.communicate()
            self.success("Lineum script finished")
            if args.outputfile != None:
                self.writeInFile(args.outputfile, output)
                self.success("You can use the following command on Linux for reading this file: less -r {0}".format(args.outputfile))
            else:
                self.success("Results of the Lineum script:")
                print output
        else:
             self.error("You have to choose a script")
             return -1
             
    def writeInFile(self,filename, data):
        '''
        '''
        self.success("Results are written in the file {0}".format(filename))
        f = open(filename, 'w')
        f.write(data)
        f.close()
