# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Error
from argparse import REMAINDER

usage  = 'Work with configuration file'
parser = PupyArgumentParser(prog='config', description=usage)
commands = parser.add_subparsers(title='commands', dest='command')

cmdlist = commands.add_parser('list', help='list configured options')
cmdlist.add_argument('section', help='list section', nargs='?', default='')
cmdlist.add_argument('-s', '--sections', help='list sections', action='store_true')

cmdset = commands.add_parser('set', help='set config option')
cmdset.add_argument('-w', '--write-project', action='store_true',
                            default=False, help='save config to project folder')
cmdset.add_argument('-W', '--write-user', action='store_true',
                            default=False, help='save config to user folder')
cmdset.add_argument('section', help='config section')
cmdset.add_argument('key', help='config key')
cmdset.add_argument('value', help='value')
cmdset.add_argument('args', nargs=REMAINDER, help='rest args')

cmdunset = commands.add_parser('unset', help='unset config option')
cmdunset.add_argument('-w', '--write-project', action='store_true',
                            default=False, help='save config to project folder')
cmdunset.add_argument('-W', '--write-user', action='store_true',
                            default=False, help='save config to user folder')
cmdunset.add_argument('section', help='config section')
cmdunset.add_argument('key', help='config key')

cmdsave = commands.add_parser('save', help='save config')
cmdsave.add_argument('-w', '--write-project', action='store_true',
                             default=True, help='save config to project folder')
cmdsave.add_argument('-W', '--write-user', action='store_true',
                             default=False, help='save config to user folder')

def do(server, handler, config, args):
    if args.command == 'list':
        for section in config.sections():
            if args.section and args.section != section:
                continue

            handler.display('[{}]'.format(section))
            if args.sections:
                continue

            for variable in config.options(section):
                handler.display('{} = {}'.format(variable, config.get(section, variable)))

            handler.display(' ')

    elif args.command == 'set':
        try:
            value = args.value
            if args.args:
                value += ' '
                value += ' '.join(args.args)

            config.set(args.section, args.key, value)
            config.save(project=args.write_project, user=args.write_user)

        except config.NoSectionError:
            handler.display(Error(args.section, 'No section'))

    elif args.command == 'unset':
        try:
            config.remove_option(args.section, args.key)
            config.save(project=args.write_project, user=args.write_user)

        except config.NoSectionError:
            handler.display(Error(args.section, 'No section'))

    elif args.command == 'save':
        config.save(project=args.write_project, user=args.write_user)
