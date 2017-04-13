# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain
from pupylib.utils.term import colorize
from datetime import datetime

__class_name__="ls"

def file_timestamp(timestamp):
    try:
        d = datetime.fromtimestamp(timestamp)
        return str(d.strftime("%d/%m/%y"))
    except:
        return '00/00/00'

def size_human_readable(num, suffix='B'):
    try:
        num = int(num)
        for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
            if abs(num) < 1024.0:
                return "%3.1f %s%s" % (num, unit, suffix)
            num /= 1024.0
        return "%.1f %s%s" % (num, 'Yi', suffix)
    except:
        return '0.00 B'

def output_format(file):
    out = u'  {}{}{}{}{}{}{}'.format(
        '{:<10}'.format(file_timestamp(file['ts'])),
        '{:<3}'.format(file['type']),
        '{:<5}'.format(file['uid']),
        '{:<5}'.format(file['gid']),
        ' {:06o} '.format(file['mode']),
        '{:<11}'.format(size_human_readable(file['size'])),
        '{:<40}'.format(file['name']))

    if file['type'] == 'D':
        out=colorize(out, 'lightyellow')
    elif 'U' in file['spec']:
        out=colorize(out, 'lightred')
    elif 'G' in file['spec']:
        out=colorize(out, 'red')
    elif file['type'] == 'B':
        out=colorize(out, 'grey')
    elif file['type'] == 'C':
        out=colorize(out, 'grey')
    elif file['type'] == 'F':
        out=colorize(out, 'cyan')
    elif file['type'] == 'S':
        out=colorize(out, 'magenta')
    elif file['type'] == 'L':
        out=colorize(out, 'grey')
    elif not file['size']:
        out=colorize(out, 'darkgrey')
    elif 'E' in file['spec']:
        out=colorize(out, 'lightgreen')
    elif 'W' in file['spec']:
        out=colorize(out, 'blue')

    return out

@config(cat="admin")
class ls(PupyModule):
    """ list system files """
    is_module=False

    dependencies = [ 'pupyutils.basic_cmds', 'scandir' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="ls", description=self.__doc__)
        self.arg_parser.add_argument('-d', '--dir', action='store_false', default=True,
                                         help='do not list directories')
        sort = self.arg_parser.add_mutually_exclusive_group()
        sort.add_argument('-s', '--size', dest='sort', action='store_const', const='size', help='sort by size')
        sort.add_argument('-t', '--time', dest='sort', action='store_const', const='ts', help='sort by time')
        self.arg_parser.add_argument('-r', '--reverse', action='store_true', default=False, help='reverse sort order')
        self.arg_parser.add_argument('path', type=str, nargs='?', help='path of a specific file')

    def run(self, args):
        results = self.client.conn.modules["pupyutils.basic_cmds"].ls(
            args.path, args.dir
        )
        results = obtain(results)

        if not results:
            return

        for r in results:
            if 'files' in r:
                self.log(r['path']+':')

                if not args.sort:
                    dirs = [
                        x for x in r['files'] if x['type'] == 'D'
                    ]

                    files = [
                        x for x in r['files'] if x['type'] != 'D'
                    ]

                    for f in sorted(dirs, key=lambda x: x['name'], reverse=args.reverse):
                        self.log(output_format(f))

                    for f in sorted(files, key=lambda x: x['name'], reverse=args.reverse):
                        self.log(output_format(f))
                else:
                    for f in sorted(r['files'], key=lambda x: x[args.sort], reverse=args.reverse):
                        self.log(output_format(f))

            else:
                self.log(output_format(r['file']))
