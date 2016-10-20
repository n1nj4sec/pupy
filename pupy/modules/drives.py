# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio
from pupylib.utils.term import colorize

__class_name__="Drives"

@config(compat=[ 'linux', 'windows' ], category='admin')
class Drives(PupyModule):
    """ List valid drives in the system """

    dependencies={
        'windows': [
            'win32api', 'win32com', 'pythoncom',
            'winerror', 'wmi', 'pupwinutils.drives'
        ],
        'linux': [ 'mount' ]
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(
            prog="drives",
            description=self.__doc__
        )

    def run(self, args):
        if self.client.is_windows():
            with redirected_stdio(self.client.conn):
                self.client.conn.modules['pupwinutils.drives'].list_drives()

        elif self.client.is_linux():
            tier1 = ( 'network', 'fuse', 'dm', 'block' )
            rmount = self.client.conn.modules['mount']
            ros = self.client.conn.modules['os']

            mountinfo = rmount.mounts()
            uid = ros.getuid()
            gid = ros.getgid()

            option_colors = {
                'rw': 'yellow',
                'nosuid': 'green',
                'nodev': 'green',
                'noexec': 'green',
                'uid': {
                    '0': 'green',
                    str(uid): 'red'
                },
                'gid': {
                    '0': 'green',
                    str(gid): 'red'
                },
                'ro': 'green',
                'user_id': {
                    '0':'green',
                    str(uid): 'red'
                },
                'group_id': {
                    '0':'green',
                    str(gid): 'red'
                },
                'allow_other': 'yellow',
                'xattr': 'yellow',
                'acl': 'yellow',
                'username': 'red',
                'domain': 'red',
                'forceuid': 'yellow',
                'forcegid': 'yellow',
                'addr': 'red',
                'unix': 'red'
            }

            def colorize_option(option):
                if len(option) > 1:
                    k, v = option
                else:
                    k = option[0]
                    v = None

                color = option_colors.get(k)
                if color:
                    if type(color) == dict:
                        if v in color:
                            return colorize(
                                '='.join([x for x in [k, v] if x]), color.get(v)
                            )
                        else:
                            return '='.join([x for x in [k, v] if x])
                    else:
                        return colorize(
                            '='.join([x for x in [k, v] if x]), color
                        )
                else:
                    return '='.join([x for x in [k, v] if x])

            for fstype in mountinfo.iterkeys():
                if fstype in tier1:
                    continue

                print '{}:'.format(colorize(fstype, 'yellow'))

                dst_max = max([len(x.dst) for x in mountinfo[fstype]])
                fsname_max = max([len(x.fsname) for x in mountinfo[fstype]])
                free_max = max([len(x.hfree) if x.total else 0 for x in mountinfo[fstype]])

                for info in mountinfo[fstype]:
                    fmt = '{{:<{}}} {{:<{}}} {{:>{}}} {{}}'.format(
                        dst_max, fsname_max, ( free_max + 3 + 4 ) if free_max else 0
                    )

                    print fmt.format(
                        info.dst, info.fsname, (
                            colorize(
                                ('{{:>3}}% ({{:>{}}})'.format(free_max)).format(
                                    info.pused, info.hfree
                                ),
                                'white' if info.pused < 90 else 'yellow'
                            )
                        ) if info.total else '',
                        ','.join([colorize_option(option) for option in info.options])
                    )

                print ''

            for fstype in tier1:
                if not fstype in mountinfo:
                    continue

                src_max = max([len(x.src) for x in mountinfo[fstype]])
                dst_max = max([len(x.dst) for x in mountinfo[fstype]])
                fsname_max = max([len(x.fsname) for x in mountinfo[fstype]])
                free_max = max([len(x.hfree) if x.total else 0 for x in mountinfo[fstype]])

                print '{}:'.format(colorize(fstype, 'green'))
                for info in mountinfo[fstype]:
                    fmt = '{{:<{}}} {{:<{}}} {{:<{}}} {{:>{}}} {{}}'.format(
                        dst_max, src_max, fsname_max, ( free_max + 3 + 4 ) if free_max else 0
                    )

                    print fmt.format(
                        info.dst, info.src, info.fsname, (
                            colorize(
                                ('{{:>3}}% ({{:>{}}})'.format(free_max)).format(
                                    info.pused, info.hfree
                                ),
                                'white' if info.pused < 90 else 'yellow'
                            )
                        ) if info.total else '',
                        ','.join([colorize_option(option) for option in info.options])
                    )

                print ''
