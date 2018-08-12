# -*- encoding: utf-8 -*-

# TODO: Fix interaction

try:
    import __builtin__ as builtins
except ImportError:
    import builtins

import readline
import code

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PythonCompleter import PythonCompleter
from pupylib.PupyOutput import Error

usage = 'Start the local python interpreter (for debugging purposes)'
parser = PupyArgumentParser(prog='python', description=usage)

def do(server, handler, config, args):
    orig_exit = builtins.exit
    orig_quit = builtins.quit

    def disabled_exit(*args, **kwargs):
        handler.display(Error('exit() disabled ! use ctrl+D to exit the python shell'))

    builtins.exit = disabled_exit
    builtins.quit = disabled_exit
    oldcompleter = readline.get_completer()

    try:
        local_ns = {
            'server': server,
            'handler': handler,
            'config': config,
        }

        readline.set_completer(PythonCompleter(local_ns=local_ns).complete)
        readline.parse_and_bind('tab: complete')
        code.interact(local=local_ns)

    except Exception as e:
        handler.display(Error(e))

    finally:
        readline.set_completer(oldcompleter)
        readline.parse_and_bind('tab: complete')
        builtins.exit = orig_exit
        builtins.quit = orig_quit
