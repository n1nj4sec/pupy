# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Table
from pupylib.utils.term import colorize
from modules.lib import size_human_readable

__class_name__="Drives"

@config(category='admin', compatibilities=['windows', 'posix', 'darwin'])
class Drives(PupyModule):
    """ List valid drives in the system """

    dependencies={
        'all': ['psutil'],
        'posix': ['mount'],
        'windows': [
            'win32api', 'win32com', 'pythoncom',
            'winerror', 'wmi', 'pupwinutils.drives'
        ],
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(
            prog="drives",
            description=cls.__doc__
        )

    def run(self, args):
        ok = False
        if self.client.is_posix():
            tier1 = ('network', 'fuse', 'dm', 'block', 'vm')

            mounts = self.client.remote('mount', 'mounts')
            getuid = self.client.remote('os', 'getuid')
            getgid = self.client.remote('os', 'getgid')

            mountinfo = mounts()
            uid = getuid()
            gid = getgid()

            option_colors = {
                'rw': 'yellow',
                'nosuid': 'grey',
                'nodev': 'grey',
                'noexec': 'lightgreen',
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

            output = []

            for fstype in mountinfo.iterkeys():
                if fstype in tier1:
                    continue

                output.append('{}:'.format(colorize(fstype, 'yellow')))

                dst_max = max([len(x['dst']) for x in mountinfo[fstype]])
                fsname_max = max([len(x['fsname']) for x in mountinfo[fstype]])
                free_max = max([len(x['hfree']) if x['total'] else 0 for x in mountinfo[fstype]])

                for info in mountinfo[fstype]:
                    fmt = '{{:<{}}} {{:<{}}} {{:>{}}} {{}}'.format(
                        dst_max, fsname_max, (free_max + 3 + 4) if free_max else 0
                    )

                    output.append(
                        fmt.format(
                            info['dst'], info['fsname'], (
                                colorize(
                                    ('{{:>3}}% ({{:>{}}})'.format(free_max)).format(
                                        info['pused'], info['hfree']
                                    ),
                                    'white' if info['pused'] < 90 else 'yellow'
                                )
                            ) if info['total'] else '',
                            ','.join([colorize_option(option) for option in info['options']])
                        )
                    )

                output.append('')

            for fstype in tier1:
                if fstype not in mountinfo:
                    continue

                src_max = max([len(x['src']) for x in mountinfo[fstype]])
                dst_max = max([len(x['dst']) for x in mountinfo[fstype]])
                fsname_max = max([len(x['fsname']) for x in mountinfo[fstype]])
                free_max = max([len(x['hfree']) if x['total'] else 0 for x in mountinfo[fstype]])

                output.append('{}:'.format(colorize(fstype, 'green')))
                for info in mountinfo[fstype]:
                    fmt = '{{:<{}}} {{:<{}}} {{:<{}}} {{:>{}}} {{}}'.format(
                        dst_max, src_max, fsname_max, (free_max + 3 + 4) if free_max else 0
                    )

                    output.append(
                        fmt.format(
                            info['dst'], info['src'], info['fsname'], (
                                colorize(
                                    ('{{:>3}}% ({{:>{}}})'.format(free_max)).format(
                                        info['pused'], info['hfree']
                                    ),
                                    'white' if info['pused'] < 90 else 'yellow'
                                )
                            ) if info['total'] else '',
                            ','.join([colorize_option(option) for option in info['options']])
                        )
                    )

                output.append('')

            self.log('\n'.join(output))

            ok = True

        elif self.client.is_windows():
            try:
                list_drives = self.client.remote('pupwinutils.drives', 'list_drives')
                self.log(list_drives())
                ok = True
            except:
                self.warning('WMI failed')
                pass

        if not ok:
            list_drives = self.client.remote('pupyps', 'drives')
            drives = list_drives()

            formatted_drives = []

            for drive in drives:
                formatted_drives.append({
                    'DEV': drive['device'],
                    'MP': drive['mountpoint'],
                    'FS': drive['fstype'],
                    'OPTS': drive['opts'],
                    'USED': (
                        '{}% ({}/{})'.format(
                            drive['percent'],
                            size_human_readable(drive['used']),
                            size_human_readable(drive['total']))
                    ) if ('used' in drive and 'total' in drive) else '?'
                })

            self.log(Table(formatted_drives, ['DEV', 'MP', 'FS', 'OPTS', 'USED']))
