# -*- coding: utf-8 -*-
# Author: @n1nj4sec
# Contributor(s): @bobsecq

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Table, Color

__class_name__ = "GetPrivsModule"


@config(compat=["windows"], cat="manage")
class GetPrivsModule(PupyModule):
    ''' Manage current process privileges '''

    dependencies = ['pupwinutils.security']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='getprivs', description=cls.__doc__)
        cls.arg_parser.add_argument(
            'privileges', nargs='*', default=None, metavar='privilege',
            help='Try to get specified privileges for the '
            'current process (SeDebugPrivilege for example)')

    def run(self, args):
        if args.privileges:
            enable_privilege = self.client.remote('pupwinutils.security', 'EnablePrivilege', False)
            for privilege in args.privileges:
                try:
                    enable_privilege(privilege)
                    self.success('{} enabled'.format(privilege))
                except Exception as e:
                    self.error('{} was not enabled: {}'.format(
                        privilege, e.args[1]))
        else:
            get_currents_privs = self.client.remote('pupwinutils.security', 'get_currents_privs', False)
            privs = get_currents_privs()

            content = []

            for (privilege, enabled) in privs:
                color = 'grey'
                if enabled:
                    color = 'green'

                content.append({
                    'Privilege': Color(privilege, color),
                    'Enabled': Color(enabled, color)
                })

            self.log(
                Table(content, ['Privilege', 'Enabled'], caption='Current priviliges')
            )
