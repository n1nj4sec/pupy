# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
import os

__class_name__="LoadPackageModule"

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def package_completer(text, line, begidx, endidx):
    try:
        l=[]
        for p in ["packages/all", "packages/linux/all/", "packages/windows/all", "packages/windows/x86", "packages/windows/amd64", "packages/android"]:
            for pkg in os.listdir(os.path.join(ROOT, p)):
                if pkg.endswith(".py"):
                    pkg=pkg[:-3]
                elif pkg.endswith((".pyc",".pyd")):
                    pkg=pkg[:-4]
                if pkg not in l and pkg.startswith(text):
                    l.append(pkg)
        return l
    except Exception as e:
        print e

@config(cat="manage", compat="all")
class LoadPackageModule(PupyModule):
    """ Load a python package onto a remote client. Packages files must be placed in one of the pupy/packages/<os>/<arch>/ repository """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="load_package", description=self.__doc__)
        self.arg_parser.add_argument('-f', '--force', action='store_true', help='force package to reload even if it has already been loaded')
        self.arg_parser.add_argument('-d', '--dll', action='store_true', help='load a dll instead')
        self.arg_parser.add_argument('package', completer=package_completer, help='package name (example: psutil, scapy, ...)')


    def run(self, args):
        if args.dll:
            if self.client.load_dll(args.package):
                self.success("dll loaded !")
            else:
                self.error("the dll was already loaded")
        else:
            if self.client.load_package(args.package, force=args.force):
                self.success("package loaded !")
            else:
                self.error("package is already loaded !")
