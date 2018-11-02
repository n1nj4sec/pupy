# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyCompleter import remote_path_completer
from pupylib.PupyOutput import Color
from modules.lib import size_human_readable, file_timestamp, to_utf8
from pupylib.utils.term import elen
from argparse import REMAINDER

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
T_ZIPFILE   = 12
T_TARFILE   = 13
T_HAS_XATTR = 14

# TODO: Rewrite using tables

def to_str(x):
    if type(x) in (str, unicode):
        return to_utf8(x)

    return str(x)

def output_format(file, windows=False, archive=None, time=False, uid_len=0, gid_len=0):
    if file[T_TYPE] == 'X':
        return '--- TRUNCATED ---'

    name = to_str(file[T_NAME])

    if archive:
        name += u' \u25bb ' + archive

    timestamp_field = u'{:<18}' if time else u'{:<10}'

    if windows:
        out = u'  {}{}{}{}{}{}'.format(
            timestamp_field.format(file_timestamp(file[T_TIMESTAMP], time)),
            u'{:<2}'.format(file[T_TYPE] + ('+' if file[T_HAS_XATTR] else '')),
            to_str(file[T_UID]).rjust(uid_len+1)+u' ' if uid_len else u'',
            to_str(file[T_GID]).rjust(gid_len+1)+u' ' if gid_len else u'',
            u'{:>9}'.format(size_human_readable(file[T_SIZE])),
            u' {:<40}'.format(name))
    else:
        if not uid_len:
            uid_len = 5

        if not gid_len:
            gid_len = 5

        out = u'  {}{}{}{}{}{}{}'.format(
            timestamp_field.format(file_timestamp(file[T_TIMESTAMP], time)),
            u'{:<2}'.format(file[T_TYPE] + ('+' if file[T_HAS_XATTR] else '')),
            to_str(file[T_UID]).rjust(uid_len+1)+' ',
            to_str(file[T_GID]).rjust(gid_len+1)+' ',
            u'{:04o} '.format(file[T_MODE] & 0o7777),
            u'{:>9}'.format(size_human_readable(file[T_SIZE])),
            u' {:<40}'.format(name))

    if archive:
        out=Color(out, 'yellow')
    elif file[T_TYPE] == 'D':
        out=Color(out, 'lightyellow')
    elif 'U' in file[T_SPEC]:
        out=Color(out, 'lightred')
    elif 'G' in file[T_SPEC]:
        out=Color(out, 'red')
    elif file[T_TYPE] == 'B':
        out=Color(out, 'grey')
    elif file[T_TYPE] == 'C':
        out=Color(out, 'grey')
    elif file[T_TYPE] == 'F':
        out=Color(out, 'cyan')
    elif file[T_TYPE] == 'S':
        out=Color(out, 'magenta')
    elif file[T_TYPE] == 'L':
        out=Color(out, 'grey')
    elif not file[T_SIZE]:
        out=Color(out, 'darkgrey')
    elif 'W' in file[T_SPEC] and not windows:
        out=Color(out, 'blue')
    elif file[T_HAS_XATTR]:
        out=Color(out, 'lightmagenta')
    elif 'E' in file[T_SPEC]:
        out=Color(out, 'lightgreen')

    return out

@config(cat="admin")
class ls(PupyModule):
    """ list system files """
    is_module=False

    dependencies = ['pupyutils.basic_cmds']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="ls", description=cls.__doc__)
        cls.arg_parser.add_argument('-d', '--dir', action='store_false', default=True,
                                         help='do not list directories')

        cls.arg_parser.add_argument('-u', '--userinfo', action='store_true', help='show uid info')
        cls.arg_parser.add_argument('-g', '--groupinfo', action='store_true', help='show gid info')

        sort = cls.arg_parser.add_mutually_exclusive_group()
        sort.add_argument('-L', '--limit', type=int, default=1024,
                          help='List no more than this amount of files (server side), '
                              'to not to stuck on huge dirs. Default: 1024')
        sort.add_argument('-A', '--archive', action='store_true', help='list archives (tar/zip)')
        sort.add_argument('-s', '--size', dest='sort', action='store_const', const=T_SIZE, help='sort by size')
        sort.add_argument('-t', '--time', dest='sort', action='store_const', const=T_TIMESTAMP, help='sort by time')
        cls.arg_parser.add_argument('-r', '--reverse', action='store_true', default=False, help='reverse sort order')
        cls.arg_parser.add_argument(
            'path', type=str, nargs=REMAINDER, help='path of a specific file', completer=remote_path_completer)

    def run(self, args):
        try:
            ls = self.client.remote('pupyutils.basic_cmds', 'ls')

            path = ' '.join(args.path)

            results = ls(
                path, args.dir, args.limit,
                args.archive, args.userinfo or args.groupinfo)

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

        show_time = args.sort == T_TIMESTAMP

        for r in results:
            uid_len = 0
            gid_len = 0

            if T_FILES in r:
                archive = None
                is_windows = windows

                if args.userinfo or args.groupinfo:
                    for x in r[T_FILES]:
                        if args.userinfo:
                            uid = x.get(T_UID, '?')
                            if type(uid) == int:
                                uid = str(uid)

                            if elen(uid) > uid_len:
                                uid_len = elen(uid)

                        if args.groupinfo:
                            gid = x.get(T_GID, '?')
                            if type(gid) == int:
                                gid = str(gid)

                            if elen(gid) > gid_len:
                                gid_len = elen(gid)

                if T_ZIPFILE in r:
                    self.log(Color('ZIP: '+r[T_ZIPFILE]+':', 'lightred'))
                    is_windows = True
                elif T_TARFILE in r:
                    self.log(Color('TAR: '+r[T_TARFILE]+':', 'lightred'))
                    is_windows = False
                elif T_PATH in r:
                    self.log(r[T_PATH]+':')

                if not args.sort:
                    dirs = []
                    files = []
                    truncated = 0

                    for x in r[T_FILES] or []:
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

                    for f in sorted(dirs, key=lambda x: to_str(x.get(T_NAME)), reverse=args.reverse):
                        self.log(output_format(f, is_windows, time=show_time, uid_len=uid_len, gid_len=gid_len))

                    for f in sorted(files, key=lambda x: to_str(x.get(T_NAME)), reverse=args.reverse):
                        self.log(output_format(f, is_windows, time=show_time, uid_len=uid_len, gid_len=gid_len))

                    if truncated:
                        self.warning('Folder is too big. Not listed: {} (-L {})'.format(
                            truncated, args.limit))

                        self.info('Summary (observed): Files: {} Dirs: {} Total: {}'.format(
                            '{}+'.format(files_cnt) if files_cnt else '??',
                            '{}+'.format(dirs_cnt) if dirs_cnt else '??',
                            total_cnt))
                    else:
                        self.info('Summary: Files: {} (size: {}) Dirs: {} Total: {}'.format(
                            files_cnt, size_human_readable(files_size), dirs_cnt, total_cnt))

                else:
                    truncated = False
                    for f in sorted(r[T_FILES], key=lambda x: x.get(args.sort), reverse=args.reverse):
                        if T_TRUNCATED in f:
                            truncated = True
                            continue

                        self.log(output_format(f, is_windows, time=show_time, uid_len=uid_len, gid_len=gid_len))

                    if truncated:
                        self.log('--- TRUNCATED ---')

            elif T_FILE in r:
                is_windows = windows
                archive = ''
                if T_ZIPFILE in r:
                    archive = 'ZIP'
                    is_windows = True
                elif T_TARFILE in r:
                    archive = 'TAR'
                    is_windows = False

                if args.userinfo:
                    uid = r[T_FILE][T_UID]
                    if type(uid) == int:
                        uid = str(uid)

                    uid_len = elen(uid)

                if args.groupinfo:
                    gid = r[T_FILE][T_GID]
                    if type(gid) == int:
                        gid = str(gid)

                    gid_len = elen(gid)

                self.log(output_format(r[T_FILE], is_windows, archive, show_time, uid_len=uid_len, gid_len=gid_len))

            else:
                self.error('Old format. Update pupyutils.basic_cmds')
                return
