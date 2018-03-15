# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Success

import logging

usage  = "Change log level"
parser = PupyArgumentParser(prog='logging', description='change pupysh logging level')
parser.add_argument(
    'level',
    choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
    default='ERROR',
    help='log level')

def do(server, handler, config, args):
    logging.getLogger().setLevel(args.level)
    handler.display(Success('Log level: {}'.format(args.level)))
