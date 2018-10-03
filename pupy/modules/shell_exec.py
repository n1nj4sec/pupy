# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from argparse import REMAINDER

__class_name__="ShellExec"


@config(cat="admin")
class ShellExec(PupyModule):
    """ execute shell commands on a remote system """

    dependencies = {
        'all': ['pupyutils.safepopen'],
        'windows': ['pupwinutils.processes']
    }

    terminate = None
    interrupted = False

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='shell_exec', description=cls.__doc__)
        cls.arg_parser.add_argument('-X', '--no-shell', action='store_true', help='Do not execute command in shell')
        cls.arg_parser.add_argument('-S', '--set-uid', help='Set UID for user (posix only)')
        cls.arg_parser.add_argument('-H', '--hide', action='store_true', help='Launch process on background '
                                                                              '(only for windows)')
        cls.arg_parser.add_argument('-c', '--codepage', default=None, help='decode using codepage')
        cls.arg_parser.add_argument(
            'argument',
            nargs=REMAINDER,
            help='shell command')

    def run(self, args):
        if not args.hide:
            check_output = self.client.remote('pupyutils.safepopen', 'check_output', False)

            cmdline = tuple(args.argument)
            if not args.no_shell:
                cmdline = ' '.join(cmdline)

            try:
                self.terminate, get_data = check_output(
                    cmdline, shell=not args.no_shell, encoding=args.codepage, suid=args.set_uid)
            except Exception as e:
                self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
                return

            data, code = get_data()
            data = data.strip()
            if not data and self.interrupted:
                return

            if code:
                if data:
                    self.log(data)
                self.error('Error code: {}'.format(code))
            else:
                if not data:
                    data = '[ NO OUTPUT ]'
                self.log(data)

        elif args.hide and self.client.is_windows():
            try:
                start_hidden_process = self.client.remote('pupwinutils.processes', 'start_hidden_process', False)
                p = start_hidden_process(args.argument)
                self.success("Process created with pid %s" % p.pid)

            except Exception as e:
                self.error("Error creating the process: %s" % e)
        else:
            self.error('--hide option works only for Windows hosts')

    def interrupt(self):
        if self.interrupted:
            return

        if self.terminate:
            self.interrupted = True
            self.terminate()
