# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from pupy.pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__="Beroot"


@config(cat="admin", compat=["linux", "windows"])
class Beroot(PupyModule):
    """Check for privilege escalation path"""

    dependencies = {
        'linux': [
            'beroot'
        ],
        'windows': [
            'pyexpat', 'xml', '_elementtree', 'xml.etree', 'win32net', 'beroot'
        ]
    }

    @classmethod
    def init_argparse(cls):
        """
        Check the project on github: https://github.com/AlessandroZ/BeRoot
        """
        header = '|====================================================================|\n'
        header += '|                                                                    |\n'
        header += '|                        The BeRoot Project                          |\n'
        header += '|                                                                    |\n'
        header += '|                          ! BANG BANG !                             |\n'
        header += '|                                                                    |\n'
        header += '|====================================================================|\n\n'

        cls.arg_parser = PupyArgumentParser(prog="beroot", description=header + cls.__doc__)
        cls.arg_parser.add_argument("-p", "--password", action="store", default=None, help="if no NOPASSWD in sudoers, "
                                                                                           "sudo -ll needs user "
                                                                                           "password (Linux only)")

    def run(self, args):

        run_beroot = self.client.remote('beroot.run', 'run')
        if self.client.is_windows():
            results = run_beroot()
            if results:
                for r in results:
                    self.windows_output(r)
            else:
                self.log('Nothing found.')
        else:
            results = run_beroot(args.password, to_print=False)
            self.log(results)

    def windows_output(self, output):
        st = '\n################ {category} ################\n'.format(category=output['category'])
        if output.get('error'):
            st += output.get('error')
        else:
            for desc, result in output.get('results'):
                if result:
                    st += '\n# %s\n' % desc
                    st += '%s\n' % result

        self.log(st)
