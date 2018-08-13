# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import readline

from modules.lib.windows.winpcap import init_winpcap
from pupylib.utils.rpyc_utils import redirected_stdo
from pupylib.PupyModule import (
    config, PupyModule, PupyArgumentParser, QA_DANGEROUS
)

__class_name__="InteractiveScapyShell"


def enqueue_output(out, queue):
    for c in iter(lambda: out.read(1), b""):
        queue.put(c)

@config(cat="admin")
class InteractiveScapyShell(PupyModule):
    """ open an interactive python shell on the remote client """

    max_clients=1
    dependencies=['pyshell']
    qa = QA_DANGEROUS

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='scapy', description=cls.__doc__)

    def run(self, args):
        init_winpcap(self.client)
        self.client.load_package('scapy', honor_ignore=False, force=True)

        try:
            with redirected_stdo(self):
                old_completer = readline.get_completer()
                try:
                    psc=self.client.conn.modules['pyshell.controller'].PyShellController()
                    readline.set_completer(psc.get_completer())
                    readline.parse_and_bind('tab: complete')
                    psc.write("from scapy.all import *")
                    while True:
                        cmd=raw_input(">>> ")
                        psc.write(cmd)
                finally:
                    readline.set_completer(old_completer)
                    readline.parse_and_bind('tab: complete')
        except KeyboardInterrupt:
            pass
