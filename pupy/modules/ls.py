# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCompleter import remote_path_completer
from pupylib.utils.rpyc_utils import obtain
from pupylib.utils.term import colorize
from modules.lib import size_human_readable, file_timestamp, to_utf8
from datetime import datetime

__class_name__="ls"

T_NAME      = 0
T_TYPE      = 1
T_SPEC      = 2
T_MODE      = 3
T_UID       = 4
T_GID       = 5
T_SIZE      = 6
T_TIMESTAMP = 7
T_PATH      = 8
T_FILES     = 9
T_FILE      = 10
T_TRUNCATED = 11

def output_format(file, windows=False):
    if windows:
        out = u'  {}{}{}{}'.format(
            u'{:<10}'.format(file_timestamp(file[T_TIMESTAMP])),
            u'{:<3}'.format(file[T_TYPE]),
            u'{:<11}'.format(size_human_readable(file[T_SIZE])),
            u'{:<40}'.format(to_utf8(file[T_NAME])))
    else:
        out = u'  {}{}{}{}{}{}{}'.format(
            u'{:<10}'.format(file_timestamp(file[T_TIMESTAMP])),
            u'{:<3}'.format(file[T_TYPE]),
            u'{:<5}'.format(file[T_UID]),
            u'{:<5}'.format(file[T_GID]),
            u' {:06o} '.format(file[T_MODE]),
            u'{:<11}'.format(size_human_readable(file[T_SIZE])),
            u'{:<40}'.format(to_utf8(file[T_NAME])))

    if file[T_TYPE] == 'D':
        out=colorize(out, 'lightyellow')
    elif 'U' in file[T_SPEC]:
        out=colorize(out, 'lightred')
    elif 'G' in file[T_SPEC]:
        out=colorize(out, 'red')
    elif file[T_TYPE] == 'B':
        out=colorize(out, 'grey')
    elif file[T_TYPE] == 'C':
        out=colorize(out, 'grey')
    elif file[T_TYPE] == 'F':
        out=colorize(out, 'cyan')
    elif file[T_TYPE] == 'S':
        out=colorize(out, 'magenta')
    elif file[T_TYPE] == 'L':
        out=colorize(out, 'grey')
    elif not file[T_SIZE]:
        out=colorize(out, 'darkgrey')
    elif 'E' in file[T_SPEC]:
        out=colorize(out, 'lightgreen')
    elif 'W' in file[T_SPEC] and not windows:
        out=colorize(out, 'blue')

    return out

@config(cat="admin")
class ls(PupyModule):
    """ list system files """
    is_module=False

    dependencies = [ 'pupyutils.basic_cmds', 'scandir' ]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="ls", description=cls.__doc__)
        cls.arg_parser.add_argument('-d', '--dir', action='store_false', default=True,
                                         help='do not list directories')
        sort = cls.arg_parser.add_mutually_exclusive_group()
        sort.add_argument('-L', '--limit', type=int, default=1024,
                          help='List no more than this amount of files (server side), '
                              'to not to stuck on huge dirs. Default: 1024')
        sort.add_argument('-s', '--size', dest='sort', action='store_const', const=T_SIZE, help='sort by size')
        sort.add_argument('-t', '--time', dest='sort', action='store_const', const=T_TIMESTAMP, help='sort by time')
        cls.arg_parser.add_argument('-r', '--reverse', action='store_true', default=False, help='reverse sort order')
        cls.arg_parser.add_argument(
            'path', type=str, nargs='?', help='path of a specific file', completer=remote_path_completer)

    def run(self, args):
        try:
            ls = self.client.remote('pupyutils.basic_cmds', 'ls')

            results = ls(args.path, args.dir, args.limit)
        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
            return

        # results = obtain(results)
        windows = self.client.is_windows()

        if not results:
            return

        total_cnt = 0
        files_size = 0
        files_cnt = 0
        dirs_cnt = 0

        for r in results:
            if T_FILES in r:
                self.log(r[T_PATH]+':')

                if not args.sort:
                    dirs = []
                    files = []
                    truncated = 0

                    for x in r[T_FILES]:
                        if T_TRUNCATED in x:
                            truncated = x[T_TRUNCATED]
                            total_cnt += truncated
                        elif x[T_TYPE] == 'D':
                            dirs.append(x)
                            total_cnt  += 1
                            dirs_cnt += 1
                        else:
                            files.append(x)
                            files_size += x[T_SIZE]
                            total_cnt  += 1
                            files_cnt  += 1

                    for f in sorted(dirs, key=lambda x: to_utf8(x[T_NAME]), reverse=args.reverse):
                        self.log(output_format(f, windows))

                    for f in sorted(files, key=lambda x: to_utf8(x[T_NAME]), reverse=args.reverse):
                        self.log(output_format(f, windows))

                    if truncated:
                        self.warning('Folder is too big. Not listed: {} (-L {})'.format(
                            truncated, args.limit))

                        self.info('Summary (observed): Files: {} Dirs: {} Total: {}'.format(
                            '{}+'.format(files_cnt) if files_cnt else '??' ,
                            '{}+'.format(dirs_cnt) if dirs_cnt else '??',
                            total_cnt))
                    else:
                        self.info('Summary: Files: {} (size: {}) Dirs: {} Total: {}'.format(
                            files_cnt, size_human_readable(files_size), dirs_cnt, total_cnt))

                else:
                    for f in sorted(r[T_FILES], key=lambda x: x[args.sort], reverse=args.reverse):
                        self.log(output_format(f, windows))

            elif T_FILE in r:
                self.log(output_format(r[T_FILE], windows))
            else:
                self.error('Old format. Update pupyutils.basic_cmds')
                return
