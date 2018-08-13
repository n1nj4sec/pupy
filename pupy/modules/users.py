# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Color

__class_name__="Users"

@config(cat="gather", compatibilities=['windows', 'linux', 'darwin'])
class Users(PupyModule):
    """ Get interactive users """

    dependencies = {
        'windows': ['win32net', 'win32api'],
        'all': ['pupyutils.users']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='users', description=cls.__doc__)
        cls.arg_parser.add_argument(
            '-g', '--groups',
            action='store_true', default=False,
            help='show groups membership')

    def run(self, args):
        users = self.client.remote('pupyutils.users', 'users')
        users_list = users()

        for user in users_list['users']:
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

            output = name

            if args.groups:
                output += u': ' + u','.join(user['groups'])

            if users_list['current'] == user['name']:
                output = u'➤ ' + output
            else:
                output = u'  ' + output

            self.log(Color(output, color))
