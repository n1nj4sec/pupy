# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Color, Table

__class_name__="Users"

@config(cat="gather", compatibilities=['windows', 'linux', 'darwin', 'posix'])
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

        objects = []

        for user in users_list['users']:
            if user['admin']:
                color = 'lightred'
            elif 'Administrators' in user['groups'] or 'sudo' in user['groups']:
                color = 'lightyellow'
            else:
                color = 'white'

            objects.append({
                'C': u'➤' if users_list['current'] == user['name'] else '',
                'NAME': Color(user['name'], color),
                'GROUPS': Color(','.join(user['groups']), color),
                'HOME': Color(user['home'], color)
            })


        headers = ['C', 'NAME', 'HOME']
        if args.groups:
            headers.insert(2, 'GROUPS')

        self.log(Table(objects, headers))
