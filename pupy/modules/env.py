# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Table, TruncateToTerm

from network.lib.convcompat import as_escaped_string


__class_name__='Env'
@config(cat='manage')
class Env(PupyModule):
    ''' List/Get/Set/Unset client environment variables '''

    dependencies = ['pupyutils.basic_cmds']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(
            prog='env', description=cls.__doc__
        )

        commands = cls.arg_parser.add_subparsers(dest="command")
        cls.arg_parser.set_defaults(func=cls.listenv)

        setenv = commands.add_parser('set')
        setenv.add_argument('name', help='Environment variable name')
        setenv.add_argument('value', help='Environment variable value')
        setenv.set_defaults(func=cls.setenv)

        getenv = commands.add_parser('get')
        getenv.add_argument('name', help='Environment variable name')
        getenv.set_defaults(func=cls.getenv)

        unsetenv = commands.add_parser('unset')
        unsetenv.add_argument('name', help='Environment variable name')
        unsetenv.set_defaults(func=cls.unsetenv)

        listenv = commands.add_parser('list')
        listenv.set_defaults(func=cls.listenv)

    def run(self, args):
        environ = self.client.remote('pupyutils.basic_cmds', 'env')
        args.func(self, args, environ)

    def setenv(self, args, environ):
        environ(args.name, args.value)

    def getenv(self, args, environ):
        value = environ(args.name)
        if value is None:
            self.error('No such variable')
        else:
            self.log(value)

    def unsetenv(self, args, environ):
        environ(args.name, None)

    def listenv(self, args, environ):
        self.log(TruncateToTerm(Table([
            {
                'VAR': k, 'VAL': as_escaped_string(v)
            } for (k, v) in environ()
        ], ['VAR', 'VAL'], legend=False)))
