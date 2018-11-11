# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Table, TruncateToTerm
from pupylib.utils.rpyc_utils import obtain

__class_name__='Env'
@config(cat='manage')
class Env(PupyModule):
    ''' List/Get/Set/Unset client environment variables '''

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='env', description=cls.__doc__)
        commands = cls.arg_parser.add_subparsers(dest="command")

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
        environ = self.client.remote('os', 'environ', False)
        args.func(self, args, environ)

    def setenv(self, args, environ):
        environ[args.name] = args.value

    def getenv(self, args, environ):
        value = environ.get(args.name, None)
        if value is None:
            self.error('No such variable')
        else:
            self.log(value)

    def unsetenv(self, args, environ):
        del environ[args.name]

    def listenv(self, args, environ):
        envvars = obtain(environ.data)
        self.log(TruncateToTerm(Table([
            {'VAR':k, 'VAL':repr(v)} for k,v in envvars.iteritems()
        ], ['VAR', 'VAL'], legend=False)))
