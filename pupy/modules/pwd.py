# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

from pupy.pupylib.PupyModule import config, PupyArgumentParser, PupyModule

if sys.version_info.major > 2:
    getcwd = 'getcwd'
    basestring = str
else:
    getcwd = 'getcwdu'

__class_name__ = 'pwd'


@config(cat="admin")
class pwd(PupyModule):
    """ Get current working dir """
    is_module=False

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="pwd", description=cls.__doc__)

    def run(self, args):
        try:
            rgetcwd = self.client.remote('os', getcwd, False)
            self.success(rgetcwd())
        except Exception as e:
            self.error(
                ' '.join(x for x in e.args if isinstance(x, basestring))
            )
