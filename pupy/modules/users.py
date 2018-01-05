# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain
from pupylib.utils.term import terminal_size, colorize

__class_name__="Users"

@config(cat="gather", compatibilities=['windows', 'linux', 'darwin'])
class Users(PupyModule):
    """ Get interactive users """

    dependencies = {
        'windows': ['win32net', 'win32api'],
        'all': ['pupyutils.users']
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='users', description=self.__doc__)
        self.arg_parser.add_argument(
            '-g', '--groups',
            action='store_true', default=False,
            help='show groups membership')

    def run(self, args):
        users = self.client.conn.modules['pupyutils.users'].users()
        users = obtain(users)

        for user in users['users']:

            if user['admin']:
                color = 'lightred'
            elif 'Administrators' in user['groups'] or 'sudo' in user['groups']:
                color = 'lightyellow'
            else:
                color = 'white'

            if type(user['name']) == unicode:
                name = user['name']
            else:
                name = user['name'].decode('utf-8')

            output = colorize(name, color)

            if args.groups:
                output += u': ' + u','.join(user['groups'])

            if users['current'] == user['name']:
                output = u'➤ ' + output
            else:
                output = u'  ' + output

            self.log(colorize(output, color))
