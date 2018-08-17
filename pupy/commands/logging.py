# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Success, Color, Table

import logging

levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR']
levels += [
    x.lower() for x in levels
]

usage  = "Show/set log level"
parser = PupyArgumentParser(prog='logging', description='change pupysh logging level')
parser.add_argument(
    '-L', '--logger', help='Apply log level only for specified logger',
    choices=logging.Logger.manager.loggerDict.keys()
)
parser.add_argument('-s', '--set-level', choices=levels, help='Set log level')
parser.add_argument('-g', '--get-level', action='store_true', help='Get log level')
parser.add_argument('level', choices=levels, nargs='?', help='Set log level')

def levelToString(level):
    return {
        logging.ERROR: 'ERROR',
        logging.WARNING: 'WARNING',
        logging.INFO: 'INFO',
        logging.DEBUG: 'DEBUG'
    }.get(level)

def levelToColor(level):
    return {
        logging.ERROR: 'grey',
        logging.WARNING: 'white',
        logging.INFO: 'yellow',
        logging.DEBUG: 'red'
    }.get(level)

def do(server, handler, config, args):
    logger = logging.getLogger(args.logger)
    if args.set_level or args.level:
        level = args.set_level or args.level
        logger.setLevel(level.upper())
        handler.display(Success('Log level: {}: {}'.format(logger.name, level)))
    elif args.get_level:
        handler.display(Success('Log level: {}'.format(
            levelToString(logger.getEffectiveLevel()))))
    else:
        objects = []
        for name, logger in logging.Logger.manager.loggerDict.iteritems():
            if not hasattr(logger, 'getEffectiveLevel'):
                continue

            level = logger.getEffectiveLevel()
            color = levelToColor(level)

            objects.append({
                'LOGGER': Color(name, color),
                'LEVEL': Color(levelToString(level), color)
            })

        objects = sorted(objects, key=lambda x: x['LOGGER'].data)

        handler.display(Table(objects, ['LOGGER', 'LEVEL']))
